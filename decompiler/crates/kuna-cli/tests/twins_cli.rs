//! Gate for `kuna twins`, the outlining report, driven through the built binary
//! on the `msvc_float_lanes.exe` fixture.
//!
//! `twins` reads bytes only — no SLEIGH, no engine — so these run with no spec.
//! The same declared range twice is the cheapest way to force one group: an
//! agent's two extents can legitimately name the same body (an alias, a jump
//! table entry and its target), and reporting both is the point.

use std::path::PathBuf;
use std::process::Command;

fn fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
        .join("decompiler/crates/kuna-analysis/tests/fixtures/msvc_float_lanes.exe")
        .to_str()
        .unwrap()
        .to_string()
}

fn run_kuna(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_kuna")).args(args).output().expect("spawn kuna");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

const BODY: &str = "0x140001000-0x140001040";

#[test]
fn a_body_declared_twice_is_one_group_of_two_sites() {
    let (stdout, stderr, code) =
        run_kuna(&["twins", &fixture(), "--define-function", BODY, "--define-function", BODY]);
    assert_eq!(code, 0, "{stderr}");
    let rows: Vec<&str> = stdout.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    for row in rows {
        let cells: Vec<&str> = row.split('\t').collect();
        assert_eq!(cells[0], "0x140001000");
        assert_eq!(cells[3], "2");
    }
}

#[test]
fn json_carries_the_same_group() {
    let (stdout, stderr, code) = run_kuna(&[
        "twins",
        &fixture(),
        "--define-function",
        BODY,
        "--define-function",
        BODY,
        "--json",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("\"groups\": 1"), "{stdout}");
    assert!(stdout.contains("\"masked_bytes\""), "{stdout}");
}

#[test]
fn a_range_without_an_end_is_skipped_and_a_twinless_pair_is_empty() {
    let (stdout, _, code) = run_kuna(&[
        "twins",
        &fixture(),
        "--define-function",
        "0x140001000",
        "--define-function",
        "0x140001000-0x140001040",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains("0x140001000"), "an unbounded range cannot be compared: {stdout}");
}

#[test]
fn no_extents_is_an_error() {
    let (_, stderr, code) = run_kuna(&["twins", &fixture()]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no --define-function"), "{stderr}");
}
