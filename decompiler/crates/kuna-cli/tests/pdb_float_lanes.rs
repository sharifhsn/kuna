//! Compile the exported C and check that copying a two-float record preserves both lanes.
use crate::common::{self, process};
use std::{fs, path::Path, process::Command};

#[test]
fn debug_typed_array_member_survives_a_whole_record_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("export");
    let (_, stderr, status) = common::run_kuna(&[
        "decompile-project", &common::fixture("pdb_float_lanes.exe"),
        "--functions", "sample_lane", "--no-asm", "-o", out.to_str().unwrap(),
        "--sleighpath", common::repo_root().join("specs").to_str().unwrap(),
    ]);
    assert_eq!(status, 0, "{stderr}");
    check_lanes(&out, "Pair");
}

#[test]
fn declared_float_return_preserves_bits_from_aliased_frame_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let image = tmp.path().join("pdb_float_lanes.exe");
    fs::copy(common::fixture("pdb_float_lanes.exe"), &image).unwrap();
    let out = tmp.path().join("export");
    let (_, stderr, status) = common::run_kuna(&[
        "decompile-project", image.to_str().unwrap(),
        "--addr", "0x140001000", "--define-function", "0x140001000=sample_lane",
        "--assert", "prototype 0x140001000 float sample_lane(void *pair, unsigned int index)",
        "--no-asm", "-o", out.to_str().unwrap(), "--sleighpath",
        common::repo_root().join("specs").to_str().unwrap(),
    ]);
    assert_eq!(status, 0, "{stderr}");
    check_lanes(&out, "unsigned long long");
}

fn check_lanes(out: &Path, storage: &str) {
    fs::write(out.join("consumer.c"), r#"
#include "pdb_float_lanes.exe.h"
#include <stdint.h>
#include <string.h>
int main(void) {
    const uint32_t bits[][2] = {{0x3fc00000,0xc0100000}, {0,0x80000000},
                                {0x7fc00123,0x7f800000}, {0xff800000,1}};
    for (unsigned i = 0; i < 4; ++i) {
        LANE_STORAGE p;
        memcpy(&p, bits[i], sizeof p);
        for (unsigned lane = 0; lane < 2; ++lane) {
            float v = sample_lane(&p, lane);
            uint32_t observed;
            memcpy(&observed, &v, sizeof observed);
            if (observed != bits[i][lane]) return 1;
        }
    }
    return 0;
}
"#.replace("LANE_STORAGE", storage)).unwrap();
    let mut compiled = false;
    for cc in ["gcc", "clang"] {
        if process::optional_output(Command::new(cc).arg("--version")).is_none() {
            continue;
        }
        for opt in ["-O0", "-O2"] {
            let output = process::required_output(Command::new(cc).current_dir(out)
                .args([opt, "-std=c11", "-Werror=int-conversion", "pdb_float_lanes.exe.c",
                       "consumer.c", "-o", "consumer"]));
            assert!(output.status.success(), "{cc} {opt}: {}", String::from_utf8_lossy(&output.stderr));
            assert!(process::required_output(&mut Command::new(out.join("consumer"))).status.success(), "{cc} {opt}");
            compiled = true;
        }
    }
    assert!(compiled, "the fixture needs a native C compiler");
}
