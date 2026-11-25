//! Integration tests for 300k `--define-function` scaling, `--only-declared`,
//! worker `funcs.decl` spill (no `E2BIG`), and `--option pdataonly on`.

use crate::common;

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

#[test]
fn only_declared_without_define_function_exits_2() {
    let bin = common::fixture("pe_reloctable_x86_64.exe");
    for argv in [
        vec!["functions", bin.as_str(), "--only-declared"],
        vec!["decompile-all", bin.as_str(), "--only-declared"],
        vec!["decompile-project", bin.as_str(), "--only-declared"],
        vec!["disassemble", bin.as_str(), "0x140001000", "--addr", "--only-declared"],
    ] {
        let (_, stderr, code) = common::run_kuna(&argv);
        assert_eq!(code, 2, "expected exit code 2 for {argv:?}, stderr: {stderr}");
        assert!(
            stderr.contains("--define-function"),
            "expected clear error naming --define-function for {argv:?}, stderr: {stderr}"
        );
    }
}

#[test]
fn only_declared_restricts_targets_without_overreporting() {
    let bin = common::fixture("pe_reloctable_x86_64.exe");
    let (stdout, stderr, code) = common::run_kuna(&[
        "functions",
        &bin,
        "--json",
        "--define-function",
        "0x140001000-0x140001010=first_fn",
        "--define-function",
        "0x140001020-0x140001060=second_fn",
        "--only-declared",
    ]);
    assert_eq!(code, 0, "functions --only-declared failed: {stderr}");
    let doc = json(&stdout);
    assert_eq!(doc["count"], 2);
    assert_eq!(doc["total"], 2);
    let names: Vec<&str> = doc["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["first_fn", "second_fn"]);

    let (stdout, stderr, code) = common::run_kuna(&[
        "decompile-all",
        &bin,
        "--json",
        "--define-function",
        "0x140001000-0x140001010=first_fn",
        "--only-declared",
    ]);
    assert_eq!(code, 0, "decompile-all --only-declared failed: {stderr}");
    let doc = json(&stdout);
    assert_eq!(doc["count"], 1);
    let funcs = doc["functions"].as_array().unwrap();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0]["name"], "first_fn");
    assert!(funcs[0]["code"].is_string(), "expected decompiled C body: {doc}");
}

#[test]
fn pdataonly_cli_restricts_pe64_entries_and_extents() {
    let reloc = common::fixture("pe_reloctable_x86_64.exe");
    let (stdout, stderr, code) = common::run_kuna(&[
        "functions",
        &reloc,
        "--json",
        "--option",
        "pdataonly",
        "on",
    ]);
    assert_eq!(code, 0, "functions --option pdataonly on failed: {stderr}");
    let doc = json(&stdout);
    assert_eq!(doc["count"], 3);
    let rows: Vec<(&str, u64)> = doc["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["address_hex"].as_str().unwrap(), f["size"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        rows,
        vec![("0x140001000", 16), ("0x140001020", 64), ("0x140001080", 8)]
    );

    let addrtaken = common::fixture("pe_addrtaken_x86_64.exe");
    let (stdout, stderr, code) = common::run_kuna(&[
        "functions",
        &addrtaken,
        "--json",
        "--mode",
        "fast",
        "--option",
        "pdataonly",
        "on",
    ]);
    assert_eq!(code, 0, "addrtaken pdataonly failed: {stderr}");
    let doc = json(&stdout);
    assert_eq!(doc["count"], 1);
    assert_eq!(doc["functions"][0]["address_hex"], "0x140001052");
}

#[test]
fn define_function_300k_with_jobs_2_no_e2big() {
    let bin = common::fixture("pe_reloctable_x86_64.exe");
    let dir = std::env::temp_dir().join(format!("kuna-300k-jobs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let decl_path = dir.join("funcs_300k.txt");

    let mut content = String::with_capacity(300_000 * 24);
    content.push_str("0x140001000-0x140001010=entry0\n");
    content.push_str("0x140001020-0x140001060=entry1\n");
    for i in 0..299_998u64 {
        use std::fmt::Write as _;
        let start = 0x200000000u64 + i * 0x20;
        let _ = writeln!(content, "0x{start:x}-0x{:x}", start + 0x10);
    }
    std::fs::write(&decl_path, &content).expect("write 300k decl file");
    let flag = format!("@{}", decl_path.display());

    let (stdout, stderr, code) = common::run_kuna(&[
        "decompile-all",
        &bin,
        "--define-function",
        &flag,
        "--only-declared",
        "--option",
        "lazyfuncs",
        "on",
        "--addr",
        "0x140001000",
        "--addr",
        "0x140001020",
        "--jobs",
        "2",
        "--json",
    ]);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(code, 0, "300k --jobs 2 failed (possible E2BIG): {stderr}");
    let doc = json(&stdout);
    assert_eq!(doc["count"], 2);
    let names: Vec<&str> = doc["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["entry0", "entry1"]);
}
