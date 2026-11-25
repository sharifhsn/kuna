//! End-to-end CLI tests for address-keyed (RVA) project output layouts,
//! memory-aligned sharding, embedded Turso (`functions.db`), `kuna query`,
//! and enriched `index.jsonl` fields.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> String {
    repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

fn specs() -> String {
    repo_root().join("specs").to_str().unwrap().to_string()
}

fn run_kuna(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kuna"))
        .args(args)
        .output()
        .expect("failed to spawn kuna")
}

fn parse_hex(raw: &str) -> u64 {
    u64::from_str_radix(raw.trim_start_matches("0x"), 16).unwrap()
}

fn verify_index_slices(dir: &Path, expect_base: u64, expect_file_prefix: Option<&str>) -> usize {
    let index_text = std::fs::read_to_string(dir.join("index.jsonl")).unwrap();
    let lines: Vec<&str> = index_text.lines().collect();
    assert!(!lines.is_empty(), "index.jsonl is empty");
    for line in &lines {
        let obj: serde_json::Value = serde_json::from_str(line).unwrap();
        let va = parse_hex(obj["addr"].as_str().unwrap());
        let rva = parse_hex(obj["rva"].as_str().unwrap());
        let end_rva = parse_hex(obj["end_rva"].as_str().unwrap());
        let size = obj["size"].as_i64().unwrap();
        let expected_rva = va.checked_sub(expect_base).unwrap_or(va);
        assert_eq!(rva, expected_rva, "rva mismatch in {line}");
        let expected_end = rva.saturating_add(u64::try_from(size).unwrap_or(0));
        assert_eq!(end_rva, expected_end, "end_rva mismatch in {line}");

        match expect_file_prefix {
            Some(prefix) => {
                let rel = obj["c_file"].as_str().unwrap();
                assert!(rel.starts_with(prefix), "unexpected c_file {rel:?} in {line}");
                let offset = obj["c_offset"].as_u64().unwrap() as usize;
                let len = obj["c_len"].as_u64().unwrap() as usize;
                let file_bytes = std::fs::read(dir.join(rel)).unwrap();
                let slice = std::str::from_utf8(&file_bytes[offset..offset + len]).unwrap();
                let name = obj["name"].as_str().unwrap();
                let addr = obj["addr"].as_str().unwrap();
                assert!(
                    slice.starts_with(&format!("// Function: {name} @ {addr}")),
                    "slice mismatch in {rel} at {offset}..+{len}: {slice:?}"
                );
            }
            None => {
                assert!(obj["c_file"].is_null(), "expected null c_file in {line}");
                assert!(obj["c_offset"].is_null(), "expected null c_offset in {line}");
                assert!(obj["c_len"].is_null(), "expected null c_len in {line}");
            }
        }
    }
    lines.len()
}

#[test]
fn invalid_layout_and_shard_align_exit_2() {
    let bin = fixture("fauxware");
    for bad in [
        vec!["decompile-project", &bin, "--layout", "unknown"],
        vec!["decompile-project", &bin, "--shard-align", "0"],
        vec!["decompile-project", &bin, "--shard-align", "0x3000"],
        vec!["decompile-project", &bin, "--shard-align", "12345"],
    ] {
        let out = run_kuna(&bad);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{bad:?} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn default_single_layout_preserves_artifacts_and_enriches_progress_index() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = fixture("fauxware");
    let sp = specs();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        tmp.path().to_str().unwrap(),
        "--progress",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    assert!(tmp.path().join("fauxware.c").is_file());
    assert!(tmp.path().join("fauxware.h").is_file());
    assert!(tmp.path().join("fauxware.asm").is_file());
    assert!(tmp.path().join("README.md").is_file());
    assert!(!tmp.path().join("slabs").exists());
    assert!(!tmp.path().join("funcs").exists());
    assert!(!tmp.path().join("functions.db").exists());
    assert!(!tmp.path().join("shards.json").exists());

    let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
    assert!(readme.contains("| Image base | `0x400000` |"), "README missing image base:\n{readme}");

    let count = verify_index_slices(tmp.path(), 0x400000, Some("fauxware.c"));
    assert!(count >= 5);
}

#[test]
fn rva_slab_and_rva_file_serial_and_stream_jobs2() {
    let bin = fixture("fauxware");
    let sp = specs();

    // Serial rva-slab with --shard-align 0x200 and --no-asm
    let slab_serial = tempfile::tempdir().unwrap();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        slab_serial.path().to_str().unwrap(),
        "--layout",
        "rva-slab",
        "--shard-align",
        "0x200",
        "--no-asm",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!slab_serial.path().join("fauxware.c").exists());
    assert!(!slab_serial.path().join("fauxware.asm").exists());
    assert!(slab_serial.path().join("fauxware.h").is_file());
    assert!(slab_serial.path().join("shards.json").is_file());
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(slab_serial.path().join("shards.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["layout"], "rva-slab");
    assert_eq!(manifest["shard_align"], "0x200");
    assert_eq!(manifest["image_base"], "0x400000");
    let shards = manifest["shards"].as_array().unwrap();
    assert!(shards.len() >= 2, "expected multiple 0x200 slabs: {manifest}");
    for s in shards {
        let rel = s["file"].as_str().unwrap();
        let text = std::fs::read_to_string(slab_serial.path().join(rel)).unwrap();
        assert!(text.starts_with("#include \"../fauxware.h\"\n\n"), "{rel}:\n{text}");
    }

    // Stream + --jobs 2 rva-slab
    let slab_stream = tempfile::tempdir().unwrap();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        slab_stream.path().to_str().unwrap(),
        "--stream",
        "--jobs",
        "2",
        "--layout",
        "rva-slab",
        "--shard-align",
        "0x200",
        "--no-asm",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!slab_stream.path().join(".streaming").exists());
    assert!(!slab_stream.path().join("fauxware.asm").exists());
    let streamed_count = verify_index_slices(slab_stream.path(), 0x400000, Some("slabs/rva_"));
    assert_eq!(streamed_count as u64, manifest["total_functions"].as_u64().unwrap());

    // Stream + --jobs 2 rva-file
    let file_stream = tempfile::tempdir().unwrap();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        file_stream.path().to_str().unwrap(),
        "--stream",
        "--jobs",
        "2",
        "--layout",
        "rva-file",
        "--no-asm",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let file_count = verify_index_slices(file_stream.path(), 0x400000, Some("funcs/rva_"));
    assert_eq!(file_count, streamed_count);
    let index_text = std::fs::read_to_string(file_stream.path().join("index.jsonl")).unwrap();
    let first: serde_json::Value = serde_json::from_str(index_text.lines().next().unwrap()).unwrap();
    let first_file = file_stream.path().join(first["c_file"].as_str().unwrap());
    let first_text = std::fs::read_to_string(&first_file).unwrap();
    assert!(first_text.starts_with("#include \"../../fauxware.h\"\n\n"));
}

#[test]
fn turso_and_both_layouts_round_trip_with_kuna_query() {
    let bin = fixture("fauxware");
    let sp = specs();

    // Serial --layout both --no-asm
    let both_dir = tempfile::tempdir().unwrap();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        both_dir.path().to_str().unwrap(),
        "--layout",
        "both",
        "--no-asm",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(both_dir.path().join("functions.db").is_file());
    assert!(both_dir.path().join("shards.json").is_file());
    assert!(both_dir.path().join("slabs").is_dir());
    assert!(!both_dir.path().join("fauxware.c").exists());
    assert!(!both_dir.path().join("fauxware.asm").exists());

    // Query summary via directory path
    let q_sum = run_kuna(&["query", both_dir.path().to_str().unwrap(), "--json"]);
    assert!(q_sum.status.success(), "stderr: {}", String::from_utf8_lossy(&q_sum.stderr));
    let sum_json: serde_json::Value = serde_json::from_slice(&q_sum.stdout).unwrap();
    assert_eq!(sum_json["meta"]["binary"], "fauxware");
    assert_eq!(sum_json["meta"]["image_base"], "0x400000");
    assert!(sum_json["counts"]["functions"].as_i64().unwrap() >= 5);
    assert!(sum_json["counts"]["sections"].as_i64().unwrap() >= 1);

    // Query --name main --json
    let db_path = both_dir.path().join("functions.db");
    let q_name = run_kuna(&["query", db_path.to_str().unwrap(), "--name", "main", "--json"]);
    assert!(q_name.status.success(), "stderr: {}", String::from_utf8_lossy(&q_name.stderr));
    let name_json: serde_json::Value = serde_json::from_slice(&q_name.stdout).unwrap();
    let funcs = name_json["functions"].as_array().unwrap();
    assert!(!funcs.is_empty(), "expected main in {name_json}");
    let main_fn = &funcs[0];
    assert_eq!(main_fn["name"], "main");
    let main_rva = main_fn["rva"].as_str().unwrap();
    assert!(
        main_fn["shard_file"].as_str().unwrap().starts_with("slabs/rva_"),
        "expected shard_file in both layout: {main_fn}"
    );
    assert!(main_fn["code"].as_str().unwrap().contains("main"));

    // Query --rva <main_rva> --json
    let q_rva = run_kuna(&["query", db_path.to_str().unwrap(), "--rva", main_rva, "--json"]);
    assert!(q_rva.status.success(), "stderr: {}", String::from_utf8_lossy(&q_rva.stderr));
    let rva_json: serde_json::Value = serde_json::from_slice(&q_rva.stdout).unwrap();
    assert_eq!(rva_json["functions"][0]["name"], "main");

    // Query --range 0x0..0x10000 --json
    let q_range =
        run_kuna(&["query", db_path.to_str().unwrap(), "--range", "0x0..0x10000", "--json"]);
    assert!(q_range.status.success(), "stderr: {}", String::from_utf8_lossy(&q_range.stderr));
    let range_json: serde_json::Value = serde_json::from_slice(&q_range.stdout).unwrap();
    assert!(range_json["functions"].as_array().unwrap().len() >= 5);

    // Query --helpers --json
    let q_helpers = run_kuna(&["query", db_path.to_str().unwrap(), "--helpers", "--json"]);
    assert!(q_helpers.status.success(), "stderr: {}", String::from_utf8_lossy(&q_helpers.stderr));
    let helpers_json: serde_json::Value = serde_json::from_slice(&q_helpers.stdout).unwrap();
    assert!(helpers_json["helpers"].as_array().unwrap().is_empty());

    // Stream --jobs 2 --layout turso --no-asm
    let turso_stream = tempfile::tempdir().unwrap();
    let out = run_kuna(&[
        "decompile-project",
        &bin,
        "-o",
        turso_stream.path().to_str().unwrap(),
        "--stream",
        "--jobs",
        "2",
        "--layout",
        "turso",
        "--no-asm",
        "--max-fn-seconds",
        "0",
        "--sleighpath",
        &sp,
    ]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(turso_stream.path().join("functions.db").is_file());
    assert!(!turso_stream.path().join("fauxware.c").exists());
    assert!(!turso_stream.path().join("slabs").exists());
    let n = verify_index_slices(turso_stream.path(), 0x400000, None);
    assert_eq!(n as i64, sum_json["counts"]["functions"].as_i64().unwrap());

    let q_stream = run_kuna(&[
        "query",
        turso_stream.path().join("functions.db").to_str().unwrap(),
        "--rva",
        main_rva,
    ]);
    assert!(q_stream.status.success());
    let text = String::from_utf8_lossy(&q_stream.stdout);
    assert!(text.contains("// Function: main @"), "{text}");
}
