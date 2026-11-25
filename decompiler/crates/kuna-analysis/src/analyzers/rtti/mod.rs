//! S1 MSVC RTTI / vftable recovery — the kuna analog of Ghidra's
//! `RttiAnalyzer` (`Ghidra/Features/MicrosoftCodeAnalyzer/.../rtti/`).
//!
//! A polymorphic C++ class compiled by MSVC carries, **entirely inside the PE
//! image** (almost always `.rdata`/`.data`), a small graph of run-time type
//! information: per class a `CompleteObjectLocator` (RTTI4) sitting immediately
//! before the class's vftable, reachable from which are a `ClassHierarchyDescriptor`
//! (RTTI3) → `BaseClassArray` (RTTI2) → `BaseClassDescriptor`s (RTTI1) → the
//! `TypeDescriptor`s (RTTI0) that carry each class's `.?A…@@`-mangled name. Without
//! parsing it, a virtual call renders `(**(code **)*plVar1)()`, the vtable slot is a
//! bare `DAT_<addr>`, and `.rdata` is raw bytes with no class names.
//!
//! This pass recovers the class names: it finds the common `type_info` vftable (the
//! pointer every RTTI0 `TypeDescriptor` shares), locates the `TypeDescriptor`s,
//! byte-searches back to each `CompleteObjectLocator` (`COL = ref − 12`), validates
//! the COL→RTTI3→RTTI2→RTTI1→RTTI0 chain, **demangles** each `.?A…@@` name via the
//! existing MSVC demangler (`demangle::demangle_rtti_class_name` — the Ghidra
//! `RttiUtil` `??_R0…@8` wrap; ZERO new demangler code), and emits:
//!   - a `Data` [`SymFact`] at each `TypeDescriptor` named `<Class>::RTTI_Type_Descriptor`;
//!   - a `Data` [`SymFact`] at each `CompleteObjectLocator` named
//!     `<Class>::RTTI_Complete_Object_Locator`;
//!   - a `Data` [`SymFact`] at the recovered vftable named `<Class>::vftable`;
//! so the decompiled output labels the metadata graph and the class names
//! (`Box`, `Shape`) surface as recovered symbols.
//!
//! # vftable discovery + virtual-method naming (R3)
//!
//! On top of the class-name recovery, the pass walks each recovered class's vftable
//! ([`vftable::walk_vftable`], the port of `VfTableModel.getVfTableCount`): from the
//! `<Class>::vftable` base it reads each pointer-width slot (an **absolute VA on both
//! arches** — vftable slots are NOT the `IBO32` displacements the COL/RTTI graph uses),
//! bounding the array at the first NULL / non-`.text` slot. For each surviving slot it
//! emits a virtual-method **function** [`SymFact`] named `<Class>::vfunc_<i>` (the
//! MSVC metadata carries the class name but not per-method names, so the slot index is
//! the disambiguator), and marks the slot array read-only ([`AnalysisOutput::readonly`]).
//! So the virtual dispatch — `(**(code **)*plVar1)()`, an unnamed `DAT_*` vtable slot
//! before — now resolves to a named function (`Box::vfunc_0` = `Box::area`).
//!
//! The slot-index name is `vfunc_<i>` and NOT `vftable_<i>`: a routine must not be named
//! after the data object that points at it. Under multiple inheritance an MSVC class
//! really does own several vftables, so `<Class>::vftable_<i>` reads as "this class's
//! i-th vftable" — which made a function inventory claim that hundreds of bytes of
//! `std::basic_stringbuf` code were vtable objects. `vfunc_<i>` names the callee, and
//! the vftable data object keeps the unindexed `<Class>::vftable` label.
//!
//! # x86 vs x64 — the one place a port goes wrong (§3.1f)
//!
//! The inter-structure references are **raw VAs on x86** but **32-bit image-base
//! relative displacements (`IBO32`) on x64**, the RTTI0 name string sits at offset
//! 8 (x86) vs 16 (x64), and the COL meta-pointer before a vftable is a full
//! pointer-width VA on both. All of this divergence is isolated in
//! [`refkind::RefKind`]; this module never branches on `is64` directly.
//!
//! # Gating + parity safety
//!
//! Default-**OFF** (`--option rtti on`), and registered only on a PE/MSVC image
//! ([`crate::passes::passes_for`] gates it on `BinaryFormat::Pe`). The XML datatest
//! path never loads a PE and never runs this pass, so the 675/675 / stage-model
//! parity oracles are structurally untouched. Defensive by construction (the
//! [`AnalysisPass`] never-fail contract): a non-PE input, a missing `type_info`
//! vftable, or any malformed structure yields an **empty** output — never a panic.

pub mod kuna_itaniumctors;
pub mod kuna_itaniumrtti;
pub mod kuna_msvcclasses;
pub mod kuna_msvchierarchy;
pub mod models;
pub mod refkind;
pub mod vftable;

use object::read::pe::{ImageNtHeaders, PeFile32, PeFile64};
use object::read::Object;
use object::{BinaryFormat, FileKind};

use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, Phase, SymFact, SymKind};
use kuna_msvchierarchy::{
    attribute_vtable_slots, recover_msvc_hierarchy, short_class_name, MsvcHierarchy,
    SlotAttribution,
};
#[cfg(test)]
use kuna_msvchierarchy::{
    find_type_descriptors, pick_common_type_info_vftable, recover_from_descriptors,
};
use models::ImageBytes;
#[cfg(test)]
use models::TypeDescriptor;
use refkind::{End, RefKind};
use vftable::TextRanges;

/// The MSVC RTTI / vftable recovery pass (gate id `rtti`). PE/MSVC path only.
#[derive(Default)]
pub struct RttiPass;

impl AnalysisPass for RttiPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "rtti"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        if ctx.file.format() != BinaryFormat::Pe {
            return out;
        }
        let Some(rk) = ref_kind_for(ctx) else {
            return out;
        };
        let img = ImageBytes::new(ctx.file);
        let text = TextRanges::new(ctx.file);
        let hier = recover_msvc_hierarchy(&img, &rk, &text);
        emit_hierarchy(&hier, &rk, &mut out);
        out
    }
}

/// Emit RTTI labels, vftable labels, read-only ranges, and ancestor-attributed
/// virtual-method slot symbols from a recovered [`MsvcHierarchy`].
pub fn emit_hierarchy(hier: &MsvcHierarchy, rk: &RefKind, out: &mut AnalysisOutput) {
    if hier.classes.is_empty() {
        return;
    }
    for cls in &hier.classes {
        out.symbols.push(SymFact {
            addr: cls.td_addr,
            name: format!("{}::RTTI_Type_Descriptor", cls.name),
            kind: SymKind::Data,
        });
        for vf in &cls.vftables {
            out.symbols.push(SymFact {
                addr: vf.col.addr,
                name: vf.col_label.clone(),
                kind: SymKind::Data,
            });
            out.symbols.push(SymFact {
                addr: vf.base,
                name: vf.label.clone(),
                kind: SymKind::Data,
            });
            out.readonly.push(vf.range(rk));
        }
    }

    let slot_attr = attribute_vtable_slots(hier);
    for (fn_addr, attr) in slot_attr {
        let SlotAttribution::Unique { class_idx, vf_idx, slot_idx } = attr else {
            continue;
        };
        let cls = &hier.classes[class_idx];
        let vf = &cls.vftables[vf_idx];
        let name = if vf.col.offset == 0 {
            vfunc_name(&cls.name, slot_idx)
        } else if let Some(bidx) = vf.owner_base_idx {
            format!("{}::vfunc_for_{}_{slot_idx}", cls.name, short_class_name(&hier.classes[bidx].name))
        } else {
            vfunc_name(&cls.name, slot_idx)
        };
        out.symbols.push(SymFact {
            addr: fn_addr,
            name,
            kind: SymKind::Function,
        });
    }
}

/// Build the [`RefKind`] for a PE `ctx`.
fn ref_kind_for(ctx: &AnalysisCtx) -> Option<RefKind> {
    ref_kind_for_raw(ctx.file, ctx.bytes)
}

pub(crate) fn ref_kind_for_raw(file: &object::File<'_>, bytes: &[u8]) -> Option<RefKind> {
    let is64 = file.is_64();
    let image_base = pe_image_base(bytes)?;
    Some(RefKind::new(is64, image_base, End::Little))
}

fn pe_image_base(bytes: &[u8]) -> Option<u64> {
    match FileKind::parse(bytes).ok()? {
        FileKind::Pe64 => {
            let pe = PeFile64::parse(bytes).ok()?;
            Some(image_base_of(&pe))
        }
        FileKind::Pe32 => {
            let pe = PeFile32::parse(bytes).ok()?;
            Some(image_base_of(&pe))
        }
        _ => None,
    }
}

fn image_base_of<Pe: ImageNtHeaders>(pe: &object::read::pe::PeFile<Pe>) -> u64 {
    pe.relative_address_base()
}

fn vfunc_name(class: &str, slot: usize) -> String {
    format!("{class}::vfunc_{slot}")
}

#[cfg(test)]
fn emit_classes(
    img: &ImageBytes,
    rk: &RefKind,
    text: &TextRanges,
    tds: &[&TypeDescriptor],
    out: &mut AnalysisOutput,
) {
    let owned: Vec<TypeDescriptor> = tds.iter().map(|t| (*t).clone()).collect();
    let hier = recover_from_descriptors(img, rk, text, &owned);
    emit_hierarchy(&hier, rk, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_identity() {
        let p = RttiPass;
        assert_eq!(p.id(), "rtti");
        assert_eq!(p.phase(), Phase::P1);
    }

    /// A recovered virtual method is named after the FUNCTION in the slot, never after
    /// the vftable data object that points at it: an inventory that labels an executable
    /// range `<Class>::vftable_<i>` claims a routine is a vtable, and under multiple
    /// inheritance a class really does own several vftables, so the indexed `vftable_`
    /// form is ambiguous rather than merely ugly.
    #[test]
    fn virtual_method_is_named_after_the_function_not_the_table() {
        assert_eq!(vfunc_name("Box", 0), "Box::vfunc_0");
        assert_eq!(vfunc_name("std::basic_stringbuf", 11), "std::basic_stringbuf::vfunc_11");
        for slot in [0usize, 1, 11] {
            let n = vfunc_name("std::bad_alloc", slot);
            assert!(
                !n.contains("vftable"),
                "a virtual-method function name must not spell the vftable data object: {n}"
            );
        }
    }

    /// Thousands of classes in an image padded to megabytes recover in one scan
    /// per byte-search: a scan per class would take minutes here.
    #[test]
    fn many_classes_recover_in_one_scan_per_search() {
        const CLASSES: u64 = 3000;
        let ib = 0x1_4000_0000u64;
        let rk = RefKind::new(true, ib, End::Little);
        let (text_base, rdata_base, data_base) = (ib + 0x1000, ib + 0x10_0000, ib + 0x20_0000);
        let put_u32 = |v: &mut [u8], off: u64, x: u64| {
            v[off as usize..off as usize + 4].copy_from_slice(&(x as u32).to_le_bytes())
        };
        let put_u64 = |v: &mut [u8], off: u64, x: u64| {
            v[off as usize..off as usize + 8].copy_from_slice(&x.to_le_bytes())
        };
        let name = |i: u64| {
            let letter = |n: u64| (b'a' + (n % 26) as u8) as char;
            format!("Klass{}{}{}", letter(i / 676), letter(i / 26), letter(i))
        };
        let mut rdata = vec![0u8; (CLASSES * 0x60) as usize];
        let mut data = vec![0u8; (CLASSES * 0x30) as usize];
        for i in 0..CLASSES {
            let (blk, td) = (i * 0x60, data_base + i * 0x30);
            put_u32(&mut rdata, blk, 1);
            put_u32(&mut rdata, blk + 12, td - ib);
            put_u32(&mut rdata, blk + 16, rdata_base + blk + 0x18 - ib);
            put_u32(&mut rdata, blk + 0x18 + 8, 1);
            put_u32(&mut rdata, blk + 0x18 + 12, rdata_base + blk + 0x28 - ib);
            put_u32(&mut rdata, blk + 0x28, rdata_base + blk + 0x30 - ib);
            put_u32(&mut rdata, blk + 0x30, td - ib);
            put_u64(&mut rdata, blk + 0x48, rdata_base + blk);
            put_u64(&mut rdata, blk + 0x50, text_base + i * 16);
            put_u64(&mut data, i * 0x30, ib + 0x2000);
            let mangled = format!(".?AV{}@@", name(i));
            let at = (i * 0x30 + 16) as usize;
            data[at..at + mangled.len()].copy_from_slice(mangled.as_bytes());
        }
        let code = vec![0u8; (CLASSES * 16) as usize];
        let padding = vec![0u8; 32 << 20];
        let img = ImageBytes::from_spans(vec![
            (text_base, &code),
            (rdata_base, &rdata),
            (data_base, &data),
            (ib + 0x100_0000, &padding),
        ]);
        let text = TextRanges::for_test(vec![(text_base, text_base + CLASSES * 16)]);

        let started = std::time::Instant::now();
        let descriptors = find_type_descriptors(&img, &rk);
        assert_eq!(pick_common_type_info_vftable(&descriptors), Some(ib + 0x2000));
        let tds: Vec<&TypeDescriptor> = descriptors.iter().collect();
        let mut out = AnalysisOutput::default();
        emit_classes(&img, &rk, &text, &tds, &mut out);
        let elapsed = started.elapsed();

        for i in [0, 1, CLASSES / 2, CLASSES - 1] {
            let class = name(i);
            let at = |n: &str| out.symbols.iter().find(|s| s.name == n).map(|s| s.addr);
            assert_eq!(at(&format!("{class}::vftable")), Some(rdata_base + i * 0x60 + 0x50));
            assert_eq!(at(&format!("{class}::vfunc_0")), Some(text_base + i * 16));
        }
        let vftables = out.symbols.iter().filter(|s| s.name.ends_with("::vftable")).count();
        assert_eq!(vftables, CLASSES as usize);
        assert!(elapsed < std::time::Duration::from_secs(30), "{CLASSES} classes took {elapsed:?}");
    }

    #[test]
    fn common_type_info_needs_agreement() {
        // A single descriptor pointing at a vftable is not enough; two are.
        let one = vec![TypeDescriptor {
            addr: 0x1000,
            p_vftable: 0x2000,
            mangled_name: ".?AVA@@".into(),
        }];
        assert_eq!(pick_common_type_info_vftable(&one), None);
        let two = vec![
            TypeDescriptor { addr: 0x1000, p_vftable: 0x2000, mangled_name: ".?AVA@@".into() },
            TypeDescriptor { addr: 0x1100, p_vftable: 0x2000, mangled_name: ".?AVB@@".into() },
        ];
        assert_eq!(pick_common_type_info_vftable(&two), Some(0x2000));
        // A null pVFTable never wins.
        let nulls = vec![
            TypeDescriptor { addr: 1, p_vftable: 0, mangled_name: ".?AVA@@".into() },
            TypeDescriptor { addr: 2, p_vftable: 0, mangled_name: ".?AVB@@".into() },
        ];
        assert_eq!(pick_common_type_info_vftable(&nulls), None);
    }
}
