//! Batch declaration scale (300k) and PE64 `pdataonly` verification.

use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_image, ConsoleProgram};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name)
}

fn specs() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
        .join("specs")
        .to_string_lossy()
        .into_owned()
}

fn load_with(image: &str, opts: &[(&str, &str)]) -> ConsoleProgram {
    let mut prog = bootstrap_from_image(fixture(image).to_str().unwrap(), "", &[specs()])
        .expect("bootstrap fixture with built processor specs");
    for &(name, value) in opts {
        prog.arch_mut().set_kuna_option(name, value).expect("settable option");
    }
    prog.commit_pending_analysis().expect("analysis commit");
    prog
}

#[test]
fn declare_functions_300k_under_five_seconds() {
    let mut prog = load_with("pe_reloctable_x86_64.exe", &[("lazyfuncs", "on")]);
    let space = prog.arch().manage().get_default_code_space().expect("code space").clone();

    let count = 300_000usize;
    let mut decls: Vec<(Address, Option<&str>, i32)> = Vec::with_capacity(count);
    decls.push((Address::new(Rc::clone(&space), 0x140001000), Some("named_first"), 0x10));
    decls.push((Address::new(Rc::clone(&space), 0x140001020), Some("named_second"), 0x40));
    for i in 0..(count - 2) {
        let vma = 0x200000000u64 + (i as u64) * 0x20;
        decls.push((Address::new(Rc::clone(&space), vma), None, 0x10));
    }

    let started = Instant::now();
    prog.declare_functions(&decls).expect("300k batch declare");
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs_f64() < 5.0,
        "300k declare_functions took {:.2}s (expected < 5s)",
        elapsed.as_secs_f64()
    );

    assert!(prog.is_declared_entry(0x140001000));
    assert_eq!(prog.declared_extent(0x140001000), 0x10);
    assert!(prog.is_declared_entry(0x140001020));
    assert_eq!(prog.declared_extent(0x140001020), 0x40);
    let mid = 0x200000000u64 + 150_000 * 0x20;
    let last = 0x200000000u64 + ((count - 3) as u64) * 0x20;
    assert!(prog.is_declared_entry(mid));
    assert_eq!(prog.declared_extent(mid), 0x10);
    assert!(prog.is_declared_entry(last));
    assert_eq!(prog.declared_extent(last), 0x10);
    assert!(!prog.is_declared_entry(last + 0x20));
}

#[test]
fn pdataonly_suppresses_speculative_pe64_entries_and_sets_extents() {
    let default_prog = load_with("pe_reloctable_x86_64.exe", &[]);
    assert!(!default_prog.arch().analysis_pdataonly, "pdataonly must default off");
    let default_addrs: Vec<u64> = default_prog
        .function_entries_canonical()
        .into_iter()
        .map(|e| e.addr.get_offset())
        .collect();
    assert!(
        default_addrs.contains(&0x140001060),
        "default PE discovery should include relocated code pointer 0x140001060: {default_addrs:#x?}"
    );

    let mut pdata_prog = load_with("pe_reloctable_x86_64.exe", &[("pdataonly", "on")]);
    let pdata_entries = pdata_prog.function_entries_canonical();
    let pdata_summary: Vec<(u64, u64)> =
        pdata_entries.iter().map(|e| (e.addr.get_offset(), e.size)).collect();
    assert_eq!(
        pdata_summary,
        vec![(0x140001000, 16), (0x140001020, 64), (0x140001080, 8)],
        "pdataonly must yield strictly .pdata entries with .pdata [Begin, End) extents"
    );

    let space = pdata_prog.arch().manage().get_default_code_space().unwrap().clone();
    pdata_prog
        .declare_function(Address::new(Rc::clone(&space), 0x140001020), Some("override_fn"), 0x20)
        .expect("override .pdata extent");
    assert_eq!(pdata_prog.declared_extent(0x140001020), 0x20);
    pdata_prog
        .declare_function(Address::new(space, 0x140001080), None, 0)
        .expect("clear .pdata extent back to unbounded");
    assert_eq!(pdata_prog.declared_extent(0x140001080), 0);

    let fast_default = load_with("pe_addrtaken_x86_64.exe", &[("fast_funcdisc", "on")]);
    let fast_pdata =
        load_with("pe_addrtaken_x86_64.exe", &[("fast_funcdisc", "on"), ("pdataonly", "on")]);
    assert!(
        fast_default.function_entries_canonical().len()
            > fast_pdata.function_entries_canonical().len(),
        "pdataonly must suppress speculative fast_funcdisc / addrtakenentry inflation"
    );
    let addrtaken_addrs: Vec<u64> = fast_pdata
        .function_entries_canonical()
        .into_iter()
        .map(|e| e.addr.get_offset())
        .collect();
    assert_eq!(addrtaken_addrs, vec![0x140001052]);

    let elf_off = load_with("fauxware", &[]);
    let elf_on = load_with("fauxware", &[("pdataonly", "on")]);
    let elf_addrs = |p: &ConsoleProgram| -> Vec<(u64, u64)> {
        p.function_entries_canonical().into_iter().map(|e| (e.addr.get_offset(), e.size)).collect()
    };
    assert_eq!(elf_addrs(&elf_off), elf_addrs(&elf_on), "pdataonly must be inert on ELF");
}
