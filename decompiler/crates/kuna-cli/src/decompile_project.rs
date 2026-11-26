//! `kuna decompile-project` — whole-binary **project export**.
//!
//! ```text
//!   kuna decompile-project <binary> [-o|--output DIR] [--functions a,b,..]
//!                          [--addr 0xVMA].. [--max-fn-seconds N]
//!                          [--stream | --progress]
//!                          [--mode auto|reliable|aggressive|fast] [--option N V]..
//!                          [--jobs N|auto] [--jobs-chunk N] [--jobs-full-load]
//!                          [--isa auto|arm|thumb] [--slice ARCH] [--target T]
//!                          [--sleighpath D]
//! ```
//!
//! Loads + analyzes the binary once (the `decompile-all` in-process path, with
//! omitted `--mode` resolved from file size) and writes a **project folder** — default
//! `<binary-filename>.kuna/` next to the binary, `-o DIR` overrides — designed
//! so a human or LLM can study the binary and attempt recompilation:
//!
//! * `<name>.c`   — every selected executable function (`// Function: <name> @ <addr>`
//!   headers, exactly the `decompile-all` rendering), `#include "<name>.h"`.
//! * `<name>.h`   — include-guarded recompile prelude (core scalar +
//!   `undefined` typedefs), the user-defined type definitions
//!   (`print_c_types`), an `extern` declaration for every global the `.c`
//!   names by address (`globalref`), and one prototype per decompiled function
//!   (`print_c_prototype` — token-identical to the `.c` definition line).
//! * `<name>.asm` — full labeled linear disassembly of every CODE section:
//!   `<name>:` labels matching the `.c` function names, per-function
//!   `; arg:` / `; stack:` comments mapping decompiled variables to stack
//!   offsets, undecodable bytes as `db` lines, and a `; --- data ---` tail
//!   listing the named globals plus every `dat_<hex>` address the `.c`
//!   references, with raw bytes.
//! * `README.md`  — binary metadata (size, arch, entry point, sections,
//!   function counts) and the artifact/labeling conventions.
//!
//! `--stream` writes the same folder INCREMENTALLY — the artifacts appear
//! before the run finishes, entry-point-first, with an `index.jsonl` per-function
//! feed and a `.streaming` status file — at the cost of a decompile-ordered
//! `.c` and an `.asm` whose variable comments move to their own section
//! ([`crate::project_stream`]).  `--progress` keeps the feed and the status file
//! but runs this module's export unchanged, so the artifacts are the non-stream
//! ones and as reproducible under `--jobs N`.
//!
//! Individual failures remain records and exit 0 while at least one body was
//! produced. A non-empty selection that produced zero bodies exits nonzero only
//! after every artifact is complete (and a streamed export has removed its
//! `.streaming` marker), with the summary on stdout and a run-level diagnostic
//! on stderr. A rejected `--assert` under `--assert-strict`, or one the pipeline
//! refused, exits nonzero the same way. Load errors, an empty target set, and I/O
//! errors also exit nonzero.
//!
//! The decompile loop and the four artifact builders live in the shared
//! decompile-project core (`kuna_console::project` — also reused by the
//! `kuna_wasm` front-end); this module keeps the CLI wrapper + orchestration.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use kuna_console::engine::ConsoleProgram;
use kuna_console::project::{
    build_asm, build_header, collect_dat_addrs,
    decompile_export_targets_with_options, export_options, render_c, rva_of, BatchOutcome,
    render_readme, FuncResult, ReadmeCounts, ReadmeFacts, ReadmeLayout,
};
use kuna_decomp::decompile_drive::{print_c_recompile_prelude, print_c_types};

use crate::decompile_all::{
    decompile_targets_pooled_with_hints, load_program, parse_args, resolve_targets, synth_base,
    Args, DriverDefaults,
};
use crate::jobs::PoolWatch;
use crate::project_db::{ProjectDbWriter, DB_FILE};
use crate::project_shards::{
    parse_shard_align, OutputLayout, ProjectExportOpts, ShardWriter, DEFAULT_SHARD_ALIGN,
    SHARDS_MANIFEST,
};
use crate::project_stream::StreamMode;

/// `kuna decompile-project` entry point.
pub fn run(argv: &[String]) -> i32 {
    // Wrapper parse: extract `-o/--output`, layout/sharding flags, intercept help,
    // reject the decompile-all-only flags, and hand the remainder to the shared parser.
    let mut output: Option<String> = None;
    let mut stream = false;
    let mut progress = false;
    let mut layout = OutputLayout::Single;
    let mut shard_align = DEFAULT_SHARD_ALIGN;
    let mut no_asm = false;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--stream" => stream = true,
            "--progress" => progress = true,
            "--no-asm" => no_asm = true,
            "--layout" => {
                if i + 1 >= argv.len() {
                    eprintln!("error: --layout requires a value");
                    usage();
                    return 2;
                }
                match OutputLayout::parse(&argv[i + 1]) {
                    Ok(v) => layout = v,
                    Err(e) => {
                        eprintln!("error: {e}");
                        usage();
                        return 2;
                    }
                }
                i += 1;
            }
            "--shard-align" => {
                if i + 1 >= argv.len() {
                    eprintln!("error: --shard-align requires a value");
                    usage();
                    return 2;
                }
                match parse_shard_align(&argv[i + 1]) {
                    Ok(v) => shard_align = v,
                    Err(e) => {
                        eprintln!("error: {e}");
                        usage();
                        return 2;
                    }
                }
                i += 1;
            }
            "-o" | "--output" => {
                if i + 1 >= argv.len() {
                    eprintln!("error: {} requires a value", argv[i]);
                    usage();
                    return 2;
                }
                output = Some(argv[i + 1].clone());
                i += 1;
            }
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "--json" | "--no-vars" => {
                eprintln!("error: {} is not a decompile-project option", argv[i]);
                usage();
                return 2;
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    let args = match parse_args(&rest, "decompile-project") {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            usage();
            return 2;
        }
    };
    let export_opts = ProjectExportOpts { layout, shard_align, no_asm };
    // `--stream` already reports progress, so it wins when both are given.
    let mode = if stream {
        Some(StreamMode::Stream)
    } else if progress {
        Some(StreamMode::Progress)
    } else {
        None
    };
    // An unqualified `--assert` directive binds to "the function under
    // decompile", which a whole-binary streamed run would apply to every one of
    // them in turn.
    if stream && !args.assertions.is_empty() {
        eprintln!(
            "error: --assert and --stream are exclusive: a streamed export decompiles every \
             function in turn, so an unqualified directive would bind to all of them. Re-run \
             without --stream."
        );
        return 2;
    }
    let run = match mode {
        Some(mode) => {
            if mode == StreamMode::Stream {
                crate::decompile_all::warn_protoorder_inert(&args.options, "decompile-project --stream");
            }
            crate::project_stream::run(&args, output.as_deref(), mode, export_opts)
        }
        None => decompile_project(&args, output.as_deref(), export_opts, None),
    };
    match run {
        Ok(completion) => emit_completion(completion),
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

pub(crate) struct ProjectCompletion {
    pub(crate) summary: String,
    pub(crate) error: Option<String>,
}

pub(crate) fn emit_completion(completion: ProjectCompletion) -> i32 {
    let status = crate::output::emit_with_status(
        &completion.summary,
        i32::from(completion.error.is_some()),
    );
    if let Some(error) = completion.error {
        eprintln!("error: {error}");
    }
    status
}

fn usage() {
    eprintln!(
        "usage: kuna decompile-project <binary> [-o|--output DIR] [--functions a,b,..] \\\n\
         \x20                   [--addr 0xVMA].. [--max-fn-seconds N] [--max-fn-memory MiB] \\\n\
         \x20                   [--layout single|rva-slab|rva-file|turso|both] \\\n\
         \x20                   [--shard-align N] [--no-asm] \\\n\
         \x20                   [--mode auto|reliable|aggressive|fast] \\\n\
         \x20                   [--jobs N|auto] [--jobs-chunk N] [--jobs-full-load] \\\n\
         \x20                   [--stream | --progress] \\\n\
         \x20                   [--define-function S[-E][=N]|@FILE].. [--only-declared] \\\n\
         \x20                   [--option N V].. [--isa auto|arm|thumb] [--slice ARCH] [--target T] [--sleighpath D]\n\
         \x20                   [--raw-image --target T --base VMA (--entry|--addr VMA)..]\n\
         \n\
         Decompile a whole binary in one in-process load and write a project folder\n\
         (default `<binary-filename>.kuna/` next to the binary; -o DIR overrides):\n\
         \x20 <name>.c    every selected executable function (#include \"<name>.h\")\n\
         \x20 <name>.h    recompile prelude + type definitions + globals named by\n\
         \x20             address + prototypes\n\
         \x20 <name>.asm  labeled disassembly (function labels, stack-var comments,\n\
         \x20             dat_<hex> data labels with raw bytes; skipped with --no-asm)\n\
         \x20 README.md   binary metadata (size, arch, image base, entry, sections, counts)\n\
         --layout controls how function C bodies are stored (default: single):\n\
         \x20 single      one monolithic <name>.c (default)\n\
         \x20 rva-slab    memory-aligned RVA slab files under src/rva_<bucket>.c + shards.json\n\
         \x20 rva-file    one file per function under funcs/0x<bucket>/0x<rva>.c + shards.json\n\
         \x20 turso       embedded SQLite-compatible functions.db (query with `kuna query`)\n\
         \x20 both        both rva-slab and functions.db\n\
         --shard-align sets the power-of-two RVA bucket granularity (default 0x10000 = 64 KiB).\n\
         --no-asm skips generating <name>.asm.\n\
         Unfiltered fast exports default to 10 seconds per function; other runs\n\
         default to 120. --max-fn-seconds overrides that policy (0 disables).\n\
         --max-fn-memory MiB stops a function once the process decompiling it\n\
         holds more than MiB resident and the function added 64 MiB or more\n\
         (omitted: under a cgroup memory cap, once it grew by the cap's margin\n\
         and the cgroup nears its cap; 0 disables).\n\
         --jobs N spreads the per-function decompile over N worker processes\n\
         (auto = this machine's parallelism, capped at 16; 1, the default, is\n\
         serial). Without --stream the artifacts are identical to a --jobs 1 run\n\
         with --option protoorder off on both, synthesized struct_N names and the\n\
         .h included: a worker cannot see another worker's callees, so the pool\n\
         does not type call arguments callee-first the way a serial export does,\n\
         nor declare a global or table an array (option elemptr)\n\
         (with --stream, workers run with structsynth off).\n\
         Progress goes to\n\
         stderr, and peak memory is roughly N times one worker's RSS.\n\
         --stream writes the folder as the run goes instead of at the end: the entry\n\
         point and what it calls are written first, index.jsonl announces each\n\
         finished function and .streaming reports progress until the export\n\
         completes. The .c is then in decompile order. Not available with --assert.\n\
         --progress keeps the live .streaming and index.jsonl feed but writes\n\
         .c/.h/.asm/README at the end, byte-identical to the export without it (so\n\
         reproducible under --jobs N), and index.jsonl in address order.\n\
         Individual function failures are recorded in the artifacts. A mixed run\n\
         exits 0; a selected set that produced no body exits 1 only after all\n\
         artifacts are complete. A rejected --assert exits 1 the same way under\n\
         --assert-strict, and a directive the pipeline refused always does.\n\
         Load errors / an empty target set / I/O errors also exit nonzero."
    );
}

pub(crate) struct WrittenSpan {
    pub(crate) c_file: Option<String>,
    pub(crate) span: Option<(u64, usize)>,
}

/// What a `--progress` export observes of [`decompile_project`]:
/// the same export, reported on while it runs.
pub(crate) trait ExportWatch: PoolWatch {
    /// Load the program; the watcher keeps its own clock running meanwhile.
    fn load(&self, args: &Args) -> Result<ConsoleProgram, String>;
    /// The target set is final and the decompile starts.
    fn decompiling(&self, prog: &ConsoleProgram, total: usize) -> Result<(), String>;
    /// The artifacts are about to be built and written.
    fn finalizing(&self);
    /// The artifacts are written; `results` and `spans` are in address order. Returns
    /// any further files it wrote, for the completion summary.
    fn written(
        &self,
        out_dir: &Path,
        image_base: u64,
        results: &[FuncResult],
        spans: &[WrittenSpan],
        c_bytes: u64,
    ) -> Result<Vec<(String, usize)>, String>;
}

/// The whole flow: load once → decompile every target (with prototypes) →
/// build the artifacts → write them all at the end.
pub(crate) fn decompile_project(
    args: &Args,
    output: Option<&str>,
    export_opts: ProjectExportOpts,
    watch: Option<&dyn ExportWatch>,
) -> Result<ProjectCompletion, String> {
    let binary_path = std::fs::canonicalize(&args.binary)
        .map_err(|_| format!("binary not found: {}", args.binary))?;
    let file_name = binary_path
        .file_name()
        .ok_or_else(|| format!("binary has no file name: {}", binary_path.display()))?
        .to_string_lossy()
        .into_owned();
    let out_dir: PathBuf = match output {
        Some(dir) => PathBuf::from(dir),
        None => binary_path
            .parent()
            .ok_or_else(|| format!("binary has no parent directory: {}", binary_path.display()))?
            .join(format!("{file_name}.kuna")),
    };

    let load_started = std::time::Instant::now();
    let mut prog = match watch {
        Some(watch) => watch.load(args)?,
        None => load_program(args, DriverDefaults::Decompile)?,
    };
    let load_seconds = load_started.elapsed().as_secs_f64();
    // Per-function watchdog — same driver policy as `decompile-all` (10 s for
    // an unfiltered fast export, 120 s otherwise, 0 disables): a non-converging
    // function becomes its own error record instead of hanging the export.
    crate::decompile_all::arm_fn_budgets(&mut prog, args);
    // (kuna outlang) The project export is C-shaped end to end: a `.c`/`.h`
    // split, a `#include`-bearing recompile prelude, and one C prototype per
    // function. Emitting a non-C body into that skeleton would produce artifacts
    // that are neither valid C nor a usable module, so this surface refuses
    // rather than half-honouring the request. `decompile` and `decompile-all`
    // carry the other languages.
    if prog.arch().print().get_name() != "c-language" {
        return Err(format!(
            "project export is C-only in this release (got {}); use `kuna decompile` or \
             `kuna decompile-all --json` for other output languages",
            prog.arch().print().get_name()
        ));
    }
    let targets = resolve_targets(&prog, args)?;
    if targets.is_empty() {
        return Err(format!("no functions selected/discovered in {}", args.binary));
    }
    crate::interior::selections(&prog, args, &targets);
    if let Some(watch) = watch {
        watch.decompiling(&prog, targets.len())?;
    }
    let mut landed = |r: &FuncResult| {
        if let Some(watch) = watch {
            watch.landed(std::slice::from_ref(r));
        }
    };

    let want_hints = export_opts.layout.writes_turso();
    let whole = args.addrs.is_empty() && args.names.is_none();
    let (callee_first, explicit) =
        crate::decompile_all::callee_first_decision(&prog, args, targets.len(), whole);
    let (mut results, pooled_types) = if args.jobs > 1 {
        if callee_first {
            eprintln!(
                "note: --jobs decompiles without the callee-first order (option protoorder, on by \
                 default), so call-argument types, and which globals and tables are arrays, can \
                 differ from a serial run; add --option protoorder off to make the two \
                 byte-identical"
            );
        }
        let inventory = prog.function_entries_canonical();
        let pooled = decompile_targets_pooled_with_hints(
            args,
            &targets,
            &inventory,
            /* want_proto= */ true,
            /* want_provenance= */ false,
            /* want_types= */ true,
            want_hints,
            load_seconds,
            synth_base(&prog),
            callee_first,
            crate::decompile_all::worker_arm_frames(&prog),
            watch.map(|w| w as &dyn PoolWatch),
        )?;
        (pooled.results, pooled.types)
    } else if callee_first {
        if explicit && !whole {
            eprintln!(
                "note: --option protoorder: {} of this binary's entries selected; a callee \
                 outside the selection is not decompiled, so it states nothing",
                targets.len()
            );
        }
        let mut base = export_options(targets.len() == 1);
        base.want_callee_hints = want_hints;
        let funcs = crate::decompile_all::decompile_callee_first(
            &mut prog, args, targets, explicit, base, &mut landed,
        );
        (funcs, None)
    } else {
        crate::decompile_all::note_custom_inert(&prog, targets.len());
        let mut opts = export_options(targets.len() == 1);
        opts.want_callee_hints = want_hints;
        (decompile_export_targets_with_options(&mut prog, targets, &opts, &mut landed), None)
    };
    if let Some(watch) = watch {
        watch.finalizing();
    }
    // Every artifact is address-ordered (resolve_targets only guarantees that
    // for the no-filter default; --addr/--functions arrive in user order).
    results.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)));

    // `print_c_types` AFTER the decompile loop: user-defined types are interned
    // into the factory as functions decompile.
    let prelude = print_c_recompile_prelude(prog.arch());
    let types = pooled_types.unwrap_or_else(|| print_c_types(prog.arch_mut()));
    let image_base = prog.image_base();

    let header = build_header(&file_name, &prelude, &types, &results)?;
    let asm = if export_opts.no_asm {
        None
    } else {
        let dat_addrs = collect_dat_addrs(&results);
        Some(build_asm(&prog, &results, &dat_addrs, &file_name))
    };
    // The CLI's `| Path |` row prints the canonicalized on-disk path (the wasm
    // front-end passes a virtual label instead), so output stays byte-identical.
    let path_label = binary_path.display().to_string();
    let facts = ReadmeFacts {
        output: export_opts,
        ..ReadmeFacts::snapshot(&binary_path, &path_label, &file_name, &prog)
    };
    let schedule = if watch.is_some() && (export_opts.no_asm || export_opts.layout != OutputLayout::Single) {
        ReadmeLayout::Progress
    } else {
        ReadmeLayout::Standard
    };
    let readme = render_readme(&facts, Some(ReadmeCounts::of(&results)), schedule);

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
    let mut sizes: Vec<(String, usize)> = Vec::new();
    let mut spans: Vec<WrittenSpan> = Vec::with_capacity(results.len());
    let mut total_c_bytes: u64 = 0;

    match export_opts.layout {
        OutputLayout::Single => {
            let c_name = format!("{file_name}.c");
            let c_path = out_dir.join(&c_name);
            let file = File::create(&c_path)
                .map_err(|e| format!("cannot create {}: {e}", c_path.display()))?;
            let mut writer = BufWriter::with_capacity(64 * 1024, file);
            let include_line = format!("#include \"{file_name}.h\"\n\n");
            writer
                .write_all(include_line.as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", c_path.display()))?;
            let mut offset = include_line.len() as u64;
            for r in &results {
                let block = render_c(std::slice::from_ref(r));
                writer
                    .write_all(block.as_bytes())
                    .map_err(|e| format!("cannot write {}: {e}", c_path.display()))?;
                spans.push(WrittenSpan {
                    c_file: Some(c_name.clone()),
                    span: Some((offset, block.len())),
                });
                offset += block.len() as u64;
            }
            writer
                .flush()
                .map_err(|e| format!("cannot flush {}: {e}", c_path.display()))?;
            total_c_bytes = offset;
            sizes.push((c_name, offset as usize));
        }
        OutputLayout::RvaSlab | OutputLayout::RvaFile | OutputLayout::Both => {
            let mut shard_writer = ShardWriter::new(
                &out_dir,
                &file_name,
                image_base,
                export_opts.layout,
                export_opts.shard_align,
                false,
            )?;
            let mut db = if export_opts.layout.writes_turso() {
                let mut w =
                    ProjectDbWriter::create(&out_dir.join(DB_FILE), image_base, export_opts.shard_align)?;
                w.write_program_metadata(&file_name, &path_label, &prog, export_opts)?;
                Some(w)
            } else {
                None
            };
            for r in &results {
                let rva = rva_of(r.address, image_base);
                let end_rva = rva.saturating_add(u64::try_from(r.size).unwrap_or(0));
                let block = render_c(std::slice::from_ref(r));
                let receipt = shard_writer.write_func(rva, end_rva, &block)?;
                if let Some(db) = db.as_mut() {
                    db.insert_function(r, Some(&receipt.rel_path))?;
                }
                spans.push(WrittenSpan {
                    c_file: Some(receipt.rel_path),
                    span: Some((receipt.offset, receipt.len)),
                });
            }
            let summary = shard_writer.finalize()?;
            total_c_bytes = summary.total_bytes;
            sizes.push((format!("{} shards", summary.shard_count), summary.total_bytes as usize));
            sizes.push((SHARDS_MANIFEST.to_string(), summary.shards_json_bytes));
            if let Some(mut db) = db {
                db.write_types_and_globals(&types, &results)?;
                let db_bytes = db.finalize()?;
                sizes.push((DB_FILE.to_string(), db_bytes as usize));
            }
        }
        OutputLayout::Turso => {
            let mut db =
                ProjectDbWriter::create(&out_dir.join(DB_FILE), image_base, export_opts.shard_align)?;
            db.write_program_metadata(&file_name, &path_label, &prog, export_opts)?;
            for r in &results {
                db.insert_function(r, None)?;
                spans.push(WrittenSpan { c_file: None, span: None });
            }
            db.write_types_and_globals(&types, &results)?;
            let db_bytes = db.finalize()?;
            sizes.push((DB_FILE.to_string(), db_bytes as usize));
        }
    }

    let h_name = format!("{file_name}.h");
    let h_path = out_dir.join(&h_name);
    std::fs::write(&h_path, &header)
        .map_err(|e| format!("cannot write {}: {e}", h_path.display()))?;
    sizes.push((h_name, header.len()));

    if let Some(asm_text) = &asm {
        let asm_name = format!("{file_name}.asm");
        let asm_path = out_dir.join(&asm_name);
        std::fs::write(&asm_path, asm_text)
            .map_err(|e| format!("cannot write {}: {e}", asm_path.display()))?;
        sizes.push((asm_name, asm_text.len()));
    }

    let readme_path = out_dir.join("README.md");
    std::fs::write(&readme_path, &readme)
        .map_err(|e| format!("cannot write {}: {e}", readme_path.display()))?;
    sizes.push(("README.md".to_string(), readme.len()));

    if let Some(watch) = watch {
        sizes.extend(watch.written(&out_dir, image_base, &results, &spans, total_c_bytes)?);
    } else if export_opts.layout != OutputLayout::Single {
        sizes.push(crate::project_stream::write_final_index(
            &out_dir, &results, &spans, image_base, export_opts,
        )?);
    }

    let ok = results.iter().filter(|r| r.error.is_none()).count();
    let failed = results.len() - ok;
    let outcomes = prog.assertion_outcomes();
    let rejected = crate::decompile_all::report_rejected_assertions(&outcomes);
    let refused = crate::decompile_all::any_refused_assertion(&outcomes);
    let assertion_error = if refused {
        Some("the pipeline refused an assertion; exported C was produced without it".to_owned())
    } else if args.assert_strict && rejected {
        Some("one or more assertions were rejected (--assert-strict)".to_owned())
    } else {
        None
    };
    let error = BatchOutcome::of(&results).all_failed_error(&args.binary).or(assertion_error);
    let files = sizes
        .iter()
        .map(|(n, s)| format!("{n} ({s} bytes)"))
        .collect::<Vec<_>>()
        .join(", ");
    let coverage = whole.then(|| kuna_console::kuna_coverage::Code::of(&prog).measure_results(&results));
    Ok(ProjectCompletion {
        summary: format!(
            "wrote {}: {files}; functions: {ok} ok, {failed} failed{}\n",
            out_dir.display(),
            coverage_clause(coverage.as_ref())
        ),
        error,
    })
}

/// (kuna `coverage`) The completion line's `; code: ...` clause: how much of the
/// program's executable bytes a whole-binary export lifted and decompiled, NUL
/// bytes no function lifted left out. Empty for a narrowed export, and when the
/// image publishes no executable bytes.
pub(crate) fn coverage_clause(coverage: Option<&kuna_console::kuna_coverage::Coverage>) -> String {
    let Some(coverage) = coverage else {
        return String::new();
    };
    let (Some(lifted), Some(decompiled)) = (coverage.lifted_share(), coverage.decompiled_share()) else {
        return String::new();
    };
    format!(
        "; code: {} lifted, {} decompiled of {} bytes",
        percent(lifted),
        percent(decompiled),
        coverage.share_total()
    )
}

/// `share` as a percentage to one decimal, never rounded up to a whole 100.
fn percent(share: f64) -> String {
    let shown = format!("{:.1}%", share * 100.0);
    if share < 1.0 && shown == "100.0%" {
        "99.9%".to_string()
    } else {
        shown
    }
}
