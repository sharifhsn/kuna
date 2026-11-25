//! End-to-end CLI tests for `--pdb <PATH>`, `--pdb=<PATH>`, `--pdb-ignore-guid`,
//! sibling PDB auto-discovery, GUID mismatch rejection, and `--jobs 2` worker propagation.

use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name)
}

fn run_kuna(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kuna"))
        .env_remove("kuna_pdb_path")
        .env_remove("KUNA_PDB_IGNORE_GUID")
        .args(args)
        .output()
        .expect("failed to spawn kuna")
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kuna-pdb-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[test]
fn pdb_sibling_autodiscovery_and_explicit_flag() {
    let dir = scratch_dir("explicit");
    let exe = dir.join("isolated.exe");
    std::fs::copy(fixture("pdb_prog.exe"), &exe).unwrap();
    let exe_s = exe.to_str().unwrap();
    let pdb_s = fixture("pdb_prog.pdb");
    let pdb_s = pdb_s.to_str().unwrap();

    // Isolated EXE with no sidecar stays stripped.
    let stripped = run_kuna(&["functions", exe_s]);
    assert!(stripped.status.success(), "{stripped:?}");
    let out = String::from_utf8_lossy(&stripped.stdout);
    assert!(!out.contains("pdb_demo_compute"), "isolated PE should stay stripped:\n{out}");

    // `--pdb <PATH>` recovers the function name.
    let with_flag = run_kuna(&["functions", exe_s, "--pdb", pdb_s]);
    assert!(with_flag.status.success(), "{with_flag:?}");
    let out = String::from_utf8_lossy(&with_flag.stdout);
    assert!(out.contains("pdb_demo_compute"), "--pdb <PATH> must recover name:\n{out}");

    // `--pdb=<PATH>` works identically.
    let eq_arg = format!("--pdb={pdb_s}");
    let with_eq = run_kuna(&["functions", &eq_arg, exe_s]);
    assert!(with_eq.status.success(), "{with_eq:?}");
    let out = String::from_utf8_lossy(&with_eq.stdout);
    assert!(out.contains("pdb_demo_compute"), "--pdb=<PATH> must recover name:\n{out}");

    // Sibling auto-discovery in the fixture directory recovers without `--pdb`.
    let sibling = run_kuna(&["functions", fixture("pdb_prog.exe").to_str().unwrap()]);
    assert!(sibling.status.success(), "{sibling:?}");
    let out = String::from_utf8_lossy(&sibling.stdout);
    assert!(out.contains("pdb_demo_compute"), "sibling auto-discovery must recover name:\n{out}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pdb_mismatch_rejected_by_default_and_accepted_with_ignore_guid() {
    let dir = scratch_dir("mismatch");
    let exe = dir.join("isolated.exe");
    std::fs::copy(fixture("pdb_prog.exe"), &exe).unwrap();
    let exe_s = exe.to_str().unwrap();
    let mismatch = fixture("pdb_prog_mismatch.pdb");
    let mismatch_s = mismatch.to_str().unwrap();

    let rejected = run_kuna(&["functions", exe_s, "--pdb", mismatch_s]);
    assert!(rejected.status.success(), "{rejected:?}");
    let stdout = String::from_utf8_lossy(&rejected.stdout);
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(!stdout.contains("other_function_xyz"), "mismatch must be rejected:\n{stdout}");
    assert!(stderr.contains("not applied"), "mismatch must log stderr note:\n{stderr}");

    let forced = run_kuna(&["functions", exe_s, "--pdb", mismatch_s, "--pdb-ignore-guid"]);
    assert!(forced.status.success(), "{forced:?}");
    let stdout = String::from_utf8_lossy(&forced.stdout);
    let stderr = String::from_utf8_lossy(&forced.stderr);
    assert!(
        stdout.contains("other_function_xyz"),
        "--pdb-ignore-guid must apply mismatched PDB:\n{stdout}"
    );
    assert!(
        stderr.contains("--pdb-ignore-guid"),
        "--pdb-ignore-guid must log stderr note:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pdb_flag_propagates_to_jobs_workers() {
    let dir = scratch_dir("jobs");
    let exe = dir.join("isolated.exe");
    std::fs::copy(fixture("pdb_cpp.exe"), &exe).unwrap();
    let exe_s = exe.to_str().unwrap();
    let pdb = fixture("pdb_cpp.pdb");
    let pdb_s = pdb.to_str().unwrap();

    let res = run_kuna(&[
        "decompile-all",
        exe_s,
        "--pdb",
        pdb_s,
        "--jobs",
        "2",
        "--functions",
        "app::Box::Box,app::util::scale",
    ]);
    assert!(res.status.success(), "stderr: {}", String::from_utf8_lossy(&res.stderr));
    let out = String::from_utf8_lossy(&res.stdout);
    assert!(out.contains("app::Box::Box"), "worker must recover app::Box::Box:\n{out}");
    assert!(out.contains("app::util::scale"), "worker must recover app::util::scale:\n{out}");

    let _ = std::fs::remove_dir_all(&dir);
}
