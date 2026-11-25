//! pdb end-to-end gate — THE HEADLINE: a Windows PE whose matching `.pdb` sits
//! beside it decompiles with its real function names, with no option line and no
//! environment variable (DIV-129).
//!
//! Fixtures (vendored under `kuna-analysis/tests/fixtures`):
//!   - `pdb_prog.exe` — a freestanding x86-64 PE built `clang -target
//!     x86_64-pc-windows-msvc -g -gcodeview -fuse-ld=lld`, so lld-link emitted a
//!     matching `pdb_prog.pdb` + the RSDS CodeView record naming it. Its function
//!     `pdb_demo_compute` carries NO leftover symbol kuna's loader names from (the
//!     COFF symtab is not a function-naming source), so without the `.pdb` it is a
//!     stripped `FUN_<addr>`.
//!   - `pdb_prog.pdb` — the matching `.pdb`, vendored **beside** the EXE, which is
//!     what the sidecar search finds.
//!   - `pdb_prog_mismatch.pdb` — a DIFFERENT `.pdb` (a different content-hash GUID),
//!     for the fingerprint-gate negative tests.
//! The build recipe + the pinned VMA/GUID are in `tests/fixtures/README.md`.
//!
//! ## What is proved
//!
//!  - **the shipped default, fixture dir**: `pdb_demo_compute` at `0x140001000`,
//!    found through the CodeView record's own filename resolved beside the image.
//!  - **`--option pdb off`**: the same function is an engine `FUN_*`/`sub_*`
//!    placeholder — proving the name is NOT a leftover symbol and that the PDB
//!    pass's value is what is visible.
//!  - **the EXE alone in a directory**: placeholder again — the sidecar, not the
//!    EXE, is where the name comes from.
//!  - **a stale `.pdb` beside the EXE** (the mismatch fixture copied to the
//!    sidecar name): placeholder — the GUID/age gate rejects it, which is what
//!    makes the automatic search safe to run by default.
//!  - **`kuna_pdb_path`**: an EXE with no sidecar still recovers its names from an
//!    explicitly supplied `.pdb`; and an explicit path that does NOT match falls
//!    through to a sidecar that does.
//!
//! Everything runs on the real-PE path (loading an actual PE), so the XML
//! datatest 675/158 oracles never reach this.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};

/// Serializes the `kuna_pdb_path` env-var dance: the pass reads the process-global
/// env at LOAD, so two tests setting it in parallel would clobber each other. Each
/// `#[test]` holds this lock for its whole body, the `verify_macho_fat` `ENV_LOCK`
/// precedent.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// The pinned VMA of `pdb_demo_compute` in `pdb_prog.exe` (ImageBase 0x140000000 +
/// RVA 0x1000). See `tests/fixtures/README.md`.
const COMPUTE_VMA: u64 = 0x140001000;

/// The function name the PDB pass recovers (the un-mangled source name).
const COMPUTE_NAME: &str = "pdb_demo_compute";

/// The env var naming the `.pdb` to apply (the fid `kuna_fid_db` precedent).
const PDB_PATH_ENV: &str = "kuna_pdb_path";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn fixtures() -> PathBuf {
    repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures")
}

struct FixtureCopy(PathBuf);

impl FixtureCopy {
    fn new(source: &Path, tag: &str) -> Self {
        let dir = common::scratch_file(tag, "dir");
        std::fs::create_dir(&dir).expect("create private test scratch");
        let exe = dir.join(source.file_name().unwrap());
        std::fs::copy(source, &exe).expect("copy the PE");
        Self(exe)
    }
}

impl Drop for FixtureCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

/// How to drive one run: which EXE to load, what `kuna_pdb_path` holds, and
/// whether the `pdb` option is explicitly turned off before the commit.
struct Run {
    exe: PathBuf,
    _copy: Option<FixtureCopy>,
    env: Option<PathBuf>,
    force_off: bool,
}

impl Run {
    /// The vendored fixture, in its own directory (the sidecar is present).
    fn fixture() -> Run {
        Run { exe: fixtures().join("pdb_prog.exe"), _copy: None, env: None, force_off: false }
    }
    /// A copy of the fixture alone in a scratch directory (no sidecar).
    fn isolated(tag: &str) -> Run {
        let copy = FixtureCopy::new(&fixtures().join("pdb_prog.exe"), tag);
        Run { exe: copy.0.clone(), _copy: Some(copy), env: None, force_off: false }
    }
    fn env(mut self, pdb: PathBuf) -> Run {
        self.env = Some(pdb);
        self
    }
    fn option_off(mut self) -> Run {
        self.force_off = true;
        self
    }
    /// Place `src` beside the EXE under the sidecar name the CodeView record uses.
    fn with_sidecar(self, src: &Path) -> Run {
        let dst = self.exe.parent().expect("the EXE has a parent").join("pdb_prog.pdb");
        std::fs::copy(src, dst).expect("install the sidecar");
        self
    }
}

/// Resolve the symbol-table name at `COMPUTE_VMA` (the engine placeholder, or the
/// PDB-recovered name).
fn name_at_compute(prog: &ConsoleProgram) -> String {
    let code_space =
        prog.arch().manage().get_default_code_space().expect("a default code space").clone();
    let addr = Address::new(std::rc::Rc::clone(&code_space), COMPUTE_VMA);
    match prog.arch().symboltab.find_function_across_scopes(&addr) {
        Some((sid, _)) => prog.arch().symboltab.symbol(sid).get_name().to_string(),
        None => prog.arch().name_function(&addr),
    }
}

/// Bootstrap the run, commit the (gated) PDB facts, and return the symbol-table name at
/// `COMPUTE_VMA`.
///
/// The `.pdb` is located by the pass at LOAD (the facts are stashed during bootstrap), so
/// `kuna_pdb_path` is set BEFORE `bootstrap_from_object` and always cleared after, so runs
/// do not leak into one another. The `option` line is applied before the deferred commit,
/// matching live-CLI ordering.
fn run(r: Run) -> String {
    let root = repo_root();
    let spec_roots = vec![root.join("specs").to_str().unwrap().to_string()];
    assert!(r.exe.exists(), "missing fixture {:?}", r.exe);

    match &r.env {
        Some(p) => std::env::set_var(PDB_PATH_ENV, p),
        None => std::env::remove_var(PDB_PATH_ENV),
    }
    let prog = bootstrap_from_object(r.exe.to_str().unwrap(), "", &spec_roots);
    std::env::remove_var(PDB_PATH_ENV);

    let mut prog = prog.expect("bootstrap fixture with built processor specs");

    if r.force_off {
        prog.arch_mut().set_kuna_option("pdb", "off").expect("pdb flips off");
    }
    prog.commit_pending_analysis().expect("analysis commit succeeds");

    name_at_compute(&prog)
}

/// Is `name` an engine-generated placeholder (`FUN_*`/`sub_*`/`func_*`/`LAB_*`)?
fn is_placeholder(name: &str) -> bool {
    name.starts_with("sub_")
        || name.starts_with("func_")
        || name.starts_with("FUN_")
        || name.starts_with("LAB_")
}

/// THE HEADLINE: the shipped default names `0x140001000` from the `.pdb` sitting
/// beside the EXE — no option line, no environment variable — and `--option pdb
/// off` puts the stripped placeholder back.
#[test]
fn pdb_sidecar_names_the_function_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let on = run(Run::fixture());
    let off = run(Run::fixture().option_off());

    eprintln!("==== 0x{COMPUTE_VMA:x}  default: {on:>24}   option off: {off:>24} ====");

    assert_eq!(
        on, COMPUTE_NAME,
        "the shipped default must name 0x{COMPUTE_VMA:x} {COMPUTE_NAME} from the sidecar .pdb"
    );
    assert!(
        is_placeholder(&off),
        "`option pdb off` must leave 0x{COMPUTE_VMA:x} a generic placeholder, got `{off}`"
    );
    assert_ne!(
        off, COMPUTE_NAME,
        "`option pdb off` must NOT name the stripped function {COMPUTE_NAME} (proves it is not a leftover symbol)"
    );
}

/// The name comes from the SIDECAR, not the EXE: the same PE alone in a directory
/// keeps its placeholder, and gains the name back as soon as the `.pdb` is put
/// beside it.
#[test]
fn pdb_name_follows_the_sidecar_file() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let alone = run(Run::isolated("alone"));
    let beside = run(Run::isolated("beside").with_sidecar(&fixtures().join("pdb_prog.pdb")));

    eprintln!("==== EXE alone: {alone:>24}   EXE + .pdb: {beside:>24} ====");

    assert!(is_placeholder(&alone), "a PE with no .pdb beside it must stay stripped, got `{alone}`");
    assert_eq!(beside, COMPUTE_NAME, "dropping the matching .pdb beside the PE must name it");
}

/// THE FINGERPRINT GATE on the automatic tier: a STALE `.pdb` sitting beside the
/// EXE under the recorded name is rejected — the function stays a placeholder.
/// This is what makes the sidecar search safe to run by default.
#[test]
fn pdb_fingerprint_gate_rejects_a_stale_sidecar() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mismatch = fixtures().join("pdb_prog_mismatch.pdb");
    assert!(mismatch.exists(), "missing mismatch fixture {mismatch:?}");

    let stale = run(Run::isolated("stale").with_sidecar(&mismatch));

    eprintln!("==== stale sidecar: {stale:>24} ====");

    assert!(
        is_placeholder(&stale),
        "a guid-mismatch .pdb beside the EXE must be rejected — 0x{COMPUTE_VMA:x} must stay a placeholder, got `{stale}`"
    );
    assert_ne!(
        stale, COMPUTE_NAME,
        "the stale .pdb must NOT recover {COMPUTE_NAME} (the fingerprint gate rejected it)"
    );
}

/// `kuna_pdb_path` still reaches a `.pdb` that is NOT beside the image, and an
/// explicit path that fails the fingerprint gate falls through to a sidecar that
/// passes it.
#[test]
fn pdb_explicit_path_is_tried_first_and_falls_through() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let matching = fixtures().join("pdb_prog.pdb");
    let mismatch = fixtures().join("pdb_prog_mismatch.pdb");

    // No sidecar anywhere near the EXE: only the env var can supply the `.pdb`.
    let explicit = run(Run::isolated("explicit").env(matching.clone()));
    // An explicit path that does not match, with a matching sidecar present.
    let fell_through = run(Run::fixture().env(mismatch.clone()));
    // An explicit path that does not match, with nothing else to fall back to.
    let nothing_left =
        run(Run::isolated("nofallback").env(mismatch));

    eprintln!(
        "==== env only: {explicit:>24}   env mismatch + sidecar: {fell_through:>24}   env mismatch alone: {nothing_left:>24} ===="
    );

    assert_eq!(explicit, COMPUTE_NAME, "kuna_pdb_path must still reach an out-of-tree .pdb");
    assert_eq!(
        fell_through, COMPUTE_NAME,
        "a mismatching explicit path must not veto a sidecar that does match"
    );
    assert!(
        is_placeholder(&nothing_left),
        "with every candidate rejected the function stays a placeholder, got `{nothing_left}`"
    );
}

/// A C++ `.pdb` names its functions with decorated publics
/// (`??0Box@app@@QEAA@H@Z`): each demangles into its namespace, a
/// compiler-generated member reads as one identifier, and the two
/// `operator delete` overloads stay two listed functions.
#[test]
fn pdb_cpp_publics_are_demangled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    std::env::remove_var(PDB_PATH_ENV);
    let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    let exe = fixtures().join("pdb_cpp.exe");
    let mut prog = bootstrap_from_object(exe.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");

    let code_space =
        prog.arch().manage().get_default_code_space().expect("a default code space").clone();
    for (vma, name) in [
        (0x140001000, "operator new"),
        (0x140001050, "app::util::scale"),
        (0x140001080, "app::Box::Box"),
        (0x1400010b0, "app::Box::~Box"),
        (0x140001140, "app::Box::scalar_deleting_destructor"),
    ] {
        let addr = Address::new(std::rc::Rc::clone(&code_space), vma);
        assert_eq!(
            prog.arch().symboltab.function_display_name_across_scopes(&addr).as_deref(),
            Some(name),
            "the function at {vma:#x}"
        );
    }
    let deletes: Vec<u64> = prog
        .function_entries_canonical()
        .iter()
        .filter(|entry| entry.name == "operator delete")
        .map(|entry| entry.addr.get_offset())
        .collect();
    assert_eq!(deletes, [0x140001030, 0x140001040], "both overloads are listed");

    // Verify TPI struct type + typed `this` prototype recovered for `app::Box`.
    let box_ty = prog
        .arch()
        .types()
        .find_by_name("app::Box")
        .expect("find app::Box")
        .expect("app::Box type must be interned from TPI");
    assert!(box_ty.get_size() > 0, "app::Box must have nonzero layout size");
    let ctor_addr = Address::new(std::rc::Rc::clone(&code_space), 0x140001080);
    let ctor_proto = prog
        .arch()
        .symboltab
        .function_proto_pieces_across_scopes(&ctor_addr)
        .expect("app::Box::Box must have a PDB prototype");
    assert!(
        ctor_proto.innames.first().map(String::as_str) == Some("this"),
        "non-static member function must prepend `this`: {ctor_proto:?}"
    );
}

#[test]
fn codeview_inline_ranges_belong_to_their_two_callers() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    std::env::remove_var(PDB_PATH_ENV);
    std::env::remove_var(kuna_decomp::kuna_loadoptions::PDB_IGNORE_GUID_ENV);
    let specs = vec![repo_root().join("specs").to_str().unwrap().to_owned()];
    let exe = fixtures().join("pdb_inline.exe");
    let mut prog = bootstrap_from_object(exe.to_str().unwrap(), "", &specs).unwrap();
    prog.commit_pending_analysis().unwrap();
    let entries = prog.function_entries_canonical();
    for name in ["sample_left", "sample_right"] {
        let base = entries.iter().find(|e| e.name == name).unwrap().addr.get_offset();
        let sites = &prog.arch().inline_sites[&base];
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].inlinee_name, "scale_and_bias");
        assert_eq!(sites[0].depth, 0);
        assert_eq!(sites[0].ranges, [(base + 1, base + 12)]);
    }
    let alone = FixtureCopy::new(&exe, "pdb-inline-alone");
    let mut bare = bootstrap_from_object(alone.0.to_str().unwrap(), "", &specs).unwrap();
    bare.commit_pending_analysis().unwrap();
    assert!(bare.arch().inline_sites.is_empty());
}

/// Optional large MSVC /O2 /Zi /GR reference build with its matching PDB.
#[test]
#[ignore = "requires an MSVC build of cpp_suite in KUNA_MSVC_FIXTURE_DIR"]
fn pdb_msvc_cpp_suite_full_recovery() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = PathBuf::from(std::env::var_os("KUNA_MSVC_FIXTURE_DIR").expect("set KUNA_MSVC_FIXTURE_DIR"));
    let exe = dir.join("cpp_suite.exe");
    let pdb = dir.join("cpp_suite.pdb");
    assert!(pdb.is_file(), "missing {}", pdb.display());
    let alone = FixtureCopy::new(&exe, "msvc-suite-alone");
    let stripped = &alone.0;

    std::env::remove_var(PDB_PATH_ENV);
    std::env::remove_var(kuna_decomp::kuna_loadoptions::PDB_IGNORE_GUID_ENV);
    let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];

    // 1. Full sibling PDB load.
    let mut prog = bootstrap_from_object(exe.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap cpp_suite.exe");
    prog.commit_pending_analysis().expect("commit cpp_suite.exe analysis");

    // Verify all expected TPI types.
    for name in ["Vec3", "EntityKind", "BitFlags", "Entity", "Serializable", "Actor", "DiamondNode"] {
        let ty = prog
            .arch()
            .types()
            .find_by_name(name)
            .expect("find_by_name")
            .unwrap_or_else(|| panic!("missing TPI type `{name}`"));
        assert!(ty.get_size() > 0, "type `{name}` must be complete, got size {}", ty.get_size());
        if name == "EntityKind" {
            assert!(ty.is_enum_type(), "EntityKind must be an enum");
        }
        if name == "BitFlags" {
            assert!(ty.has_bitfields(), "BitFlags must carry bitfields");
        }
    }

    // Verify typed prototypes (with `this` on member functions).
    let code_space =
        prog.arch().manage().get_default_code_space().expect("default code space").clone();
    let find_func_vma = |p: &ConsoleProgram, want: &str| -> u64 {
        p.function_entries_canonical()
            .iter()
            .find(|e| e.name == want)
            .unwrap_or_else(|| panic!("missing function `{want}`"))
            .addr
            .get_offset()
    };
    for member in ["Actor::tick", "Actor::compute_score", "Actor::serialize"] {
        let vma = find_func_vma(&prog, member);
        let addr = Address::new(std::rc::Rc::clone(&code_space), vma);
        let proto = prog
            .arch()
            .symboltab
            .function_proto_pieces_across_scopes(&addr)
            .unwrap_or_else(|| panic!("missing PDB prototype for `{member}`"));
        assert_eq!(
            proto.innames.first().map(String::as_str),
            Some("this"),
            "`{member}` must have `this` parameter: {proto:?}"
        );
    }
    let poly_vma = find_func_vma(&prog, "run_polymorphic");
    let poly_proto = prog
        .arch()
        .symboltab
        .function_proto_pieces_across_scopes(&Address::new(std::rc::Rc::clone(&code_space), poly_vma))
        .expect("run_polymorphic prototype");
    assert_eq!(poly_proto.intypes.len(), 3, "run_polymorphic has 3 params");

    // Verify typed globals (`g_world_origin` and `g_default_kind`).
    let global_scope = prog.arch().symboltab.get_global_scope().expect("global scope");
    for (gname, want_ty) in [("g_world_origin", "Vec3"), ("g_default_kind", "EntityKind")] {
        let sids = prog.arch().symboltab.find_by_name(global_scope, gname);
        let found_ty = sids
            .iter()
            .filter_map(|&sid| {
                prog.arch()
                    .symboltab
                    .symbol(sid)
                    .dtype
                    .as_ref()
                    .map(|t| t.get_name().to_string())
            })
            .find(|t| t == want_ty);
        assert_eq!(
            found_ty.as_deref(),
            Some(want_ty),
            "expected global `{gname}` typed as `{want_ty}`"
        );
    }

    // Verify locals recovered (`buf` in `run_polymorphic`).
    let poly_locals = prog.dwarf_locals_for(poly_vma);
    assert!(
        poly_locals.iter().any(|(n, _, _, _)| n == "buf"),
        "stack local `buf` missing from run_polymorphic: {poly_locals:?}"
    );
    let total_locals: usize = prog
        .function_entries_canonical()
        .iter()
        .map(|e| prog.dwarf_locals_for(e.addr.get_offset()).len())
        .sum();

    // Verify `S_INLINESITE` parked on `Architecture::inline_sites` (including `mix_hash_helper`
    // inlined in all 6 `heavy_caller_1..6`!).
    let total_inline_callers = prog.arch().inline_sites.len();
    let total_inline_sites: usize = prog.arch().inline_sites.values().map(Vec::len).sum();
    let mut mix_hash_sites = 0usize;
    for idx in 1..=6 {
        let cname = format!("heavy_caller_{idx}");
        let cvma = find_func_vma(&prog, &cname);
        let sites = prog
            .arch()
            .inline_sites
            .get(&cvma)
            .unwrap_or_else(|| panic!("no inline_sites parked for `{cname}`"));
        let count = sites
            .iter()
            .filter(|s| s.inlinee_name == "mix_hash_helper" && !s.ranges.is_empty())
            .count();
        assert!(
            count >= 2,
            "expected >=2 mix_hash_helper inline sites in `{cname}`, got {count}"
        );
        mix_hash_sites += count;
    }

    let proto_count = prog
        .function_entries_canonical()
        .iter()
        .filter(|e| prog.arch().symboltab.function_proto_pieces_across_scopes(&e.addr).is_some())
        .count();
    eprintln!(
        "==== cpp_suite PDB summary: functions={} prototypes={} globals={} locals={} inline_callers={} inline_sites={} mix_hash_in_heavy_callers={} ====",
        prog.function_entries_canonical().len(),
        proto_count,
        prog.global_data_symbols().len(),
        total_locals,
        total_inline_callers,
        total_inline_sites,
        mix_hash_sites,
    );

    // 2. Stripped copy WITHOUT PDB must be completely inert.
    let mut bare = bootstrap_from_object(stripped.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap stripped");
    bare.commit_pending_analysis().expect("commit stripped");
    assert!(bare.arch().inline_sites.is_empty(), "stripped PE without PDB must have no inline_sites");
    assert!(
        bare.function_entries_canonical().iter().all(|e| e.name != "run_polymorphic"),
        "stripped PE without PDB must not name run_polymorphic"
    );

    // 3. Stripped copy WITH explicit `kuna_pdb_path` recovers everything.
    std::env::set_var(PDB_PATH_ENV, &pdb);
    let mut restored = bootstrap_from_object(stripped.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap stripped with pdb");
    std::env::remove_var(PDB_PATH_ENV);
    restored.commit_pending_analysis().expect("commit stripped with pdb");
    assert!(
        restored.function_entries_canonical().iter().any(|e| e.name == "run_polymorphic"),
        "stripped PE with --pdb must recover run_polymorphic"
    );
    assert_eq!(
        restored.arch().inline_sites.len(),
        total_inline_callers,
        "stripped PE with --pdb must recover identical inline_sites"
    );
}
