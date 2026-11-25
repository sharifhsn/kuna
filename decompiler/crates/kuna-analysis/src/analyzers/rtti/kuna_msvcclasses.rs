//! Full MSVC C++ class recovery (Ghidra `RTTIWindowsClassRecoverer` parity):
//! adjustor/vtordisp thunks, deleting destructors, constructors/destructors,
//! `/OPT:ICF` safety guard, and deterministic pre-decompile member layout synthesis.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_decomp::architecture::Architecture;
use kuna_decomp::fspec::{effect_type, EXTRAPOP_UNKNOWN};
use kuna_decomp::kuna_fasthash::{FxHashMap, FxHashSet};
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::translate::{PcodeEmit, Translate};
use object::read::{Object, ObjectSection, ObjectSymbol};
use object::BinaryFormat;

use crate::pass::{AnalysisOutput, SymFact, SymKind};

use super::kuna_msvchierarchy::{
    attribute_vtable_slots, recover_msvc_hierarchy, short_class_name, MsvcHierarchy,
    SlotAttribution,
};
use super::models::ImageBytes;
use super::refkind::RefKind;
use super::vftable::TextRanges;

const MAX_THUNK_INSNS: usize = 8;
const MAX_DTOR_INSNS: usize = 96;
const MAX_CTOR_INSNS: usize = 256;
const MAX_LAYOUT_INSNS: usize = 512;
const MAX_MEMBER_OFFSET: u32 = 0x10000;

/// Pure-data class recovery payload committed into `TypeFactory` and the engine
/// only when `--option rtti on` (classes mode) is active.
#[derive(Clone, Debug, Default)]
pub struct MsvcClassRecoveryData {
    pub ptr_size: usize,
    pub is_64: bool,
    pub classes: Vec<RecoveredMsvcClass>,
    pub function_symbols: Vec<SymFact>,
    pub methods: Vec<RecoveredMsvcMethod>,
}

/// One recovered MSVC class ready for topological struct materialization.
#[derive(Clone, Debug)]
pub struct RecoveredMsvcClass {
    pub name: String,
    pub size: u32,
    pub align: u32,
    pub vftables: Vec<RecoveredVfTableSpec>,
    pub fields: Vec<RecoveredClassField>,
}

/// One vftable struct to materialize and bind as a `TypedDataFact`.
#[derive(Clone, Debug)]
pub struct RecoveredVfTableSpec {
    pub base_addr: u64,
    pub label: String,
    pub struct_name: String,
    pub col_offset: u32,
    pub owner_class_idx: Option<usize>,
    pub slots: Vec<RecoveredVfSlot>,
}

/// One slot field inside a materialized `<Class>_vftable` struct.
#[derive(Clone, Debug)]
pub struct RecoveredVfSlot {
    pub target_addr: u64,
    pub field_name: String,
    pub is_deleting_dtor: bool,
}

/// One non-overlapping field inside a materialized `<Class>` struct.
#[derive(Clone, Debug)]
pub struct RecoveredClassField {
    pub offset: u32,
    pub name: String,
    pub kind: RecoveredFieldKind,
}

/// Type category of a recovered class field.
#[derive(Clone, Debug)]
pub enum RecoveredFieldKind {
    VftablePtr { vftable_struct_name: String },
    Vbptr,
    VtorDisp,
    BaseSubobject { base_class_idx: usize },
    Primitive { width: u32, hint: FieldTypeHint },
}

/// Inferred primitive metatype from p-code operations on a member field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldTypeHint {
    Uint,
    Int,
    Float,
    VoidPtr,
}

/// Recovered method classification used to lock `this` and exact dtor prototypes.
#[derive(Clone, Debug)]
pub struct RecoveredMsvcMethod {
    pub addr: u64,
    pub name: String,
    pub this_class_idx: usize,
    pub kind: RecoveredMethodKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveredMethodKind {
    Ctor,
    Dtor,
    DeletingDtor,
    VirtualMethod,
    AdjustorThunk,
}

#[derive(Clone, Copy, Debug)]
enum ThunkKind {
    Adjustor { delta: i64, target: u64 },
    VtorDisp { constant_delta: i64, target: u64 },
}

/// Run full MSVC class recovery on a PE image using only deterministic load-time
/// inputs (independent of `fast_funcdisc` / `Listing` so `--jobs N` workers match).
pub fn run_msvc_class_recovery(
    file: &object::File<'_>,
    bytes: &[u8],
    arch: &Architecture,
    translate: &dyn Translate,
    known_entries: &[u64],
) -> AnalysisOutput {
    let mut out = AnalysisOutput::default();
    if file.format() != BinaryFormat::Pe {
        return out;
    }
    let Some(rk) = super::ref_kind_for_raw(file, bytes) else {
        return out;
    };
    let img = ImageBytes::new(file);
    let text = TextRanges::new(file);
    let hier = recover_msvc_hierarchy(&img, &rk, &text);
    if hier.classes.is_empty() {
        return out;
    }

    let Some(walker) = MsvcWalker::new(arch, translate, &rk) else {
        return out;
    };

    let slot_attr = attribute_vtable_slots(&hier);
    let purecall_addrs = detect_purecall(file, &hier, &slot_attr, &walker);
    let mut icf_blocked: FxHashSet<u64> = purecall_addrs.clone();
    for (&addr, attr) in &slot_attr {
        if matches!(attr, SlotAttribution::IcfShared { .. }) {
            icf_blocked.insert(addr);
        }
    }

    // Step A: decode adjustor and vtordisp thunks in secondary/virtual-base vftables.
    let mut thunks: BTreeMap<u64, (usize, usize, usize, ThunkKind)> = BTreeMap::new();
    let mut thunk_targets: BTreeMap<u64, Vec<(usize, usize, usize, ThunkKind)>> = BTreeMap::new();
    for (c, cls) in hier.classes.iter().enumerate() {
        for (vf_idx, vf) in cls.vftables.iter().enumerate() {
            if vf.col.offset == 0 {
                continue;
            }
            for (slot_idx, &slot_addr) in vf.slots.iter().enumerate() {
                if icf_blocked.contains(&slot_addr) {
                    continue;
                }
                if let Some(kind) = decode_adjustor_thunk(&walker, &text, slot_addr) {
                    let target = match kind {
                        ThunkKind::Adjustor { target, .. } | ThunkKind::VtorDisp { target, .. } => {
                            target
                        }
                    };
                    thunks.entry(slot_addr).or_insert((c, vf_idx, slot_idx, kind));
                    thunk_targets.entry(target).or_default().push((c, vf_idx, slot_idx, kind));
                }
            }
        }
    }

    // Check if any thunk target is claimed by unrelated classes (/OPT:ICF guard).
    for (&target, claimants) in &thunk_targets {
        let mut uniq: Vec<usize> = claimants.iter().map(|&(c, ..)| c).collect();
        uniq.sort_unstable();
        uniq.dedup();
        let maximal: Vec<usize> = uniq
            .iter()
            .copied()
            .filter(|&c| !uniq.iter().any(|&o| o != c && hier.classes[c].ancestors.contains(&o)))
            .collect();
        if maximal.len() > 1 {
            icf_blocked.insert(target);
        }
    }

    // Step B: locate operator delete and scalar/vector deleting destructors + inner ~C.
    let (delete_addrs, deleting_dtors, inner_dtor_candidates, known_sizes) =
        detect_deleting_destructors(
            file,
            &hier,
            &slot_attr,
            &thunks,
            &icf_blocked,
            &walker,
            &text,
        );
    let _ = &delete_addrs;

    // Resolve inner destructor candidates with ancestor-winner & ICF guard.
    let mut class_dtors: BTreeMap<u64, usize> = BTreeMap::new();
    {
        let mut by_addr: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (cls_idx, dtor_addr) in inner_dtor_candidates {
            by_addr.entry(dtor_addr).or_default().push(cls_idx);
        }
        for (dtor_addr, mut claimants) in by_addr {
            claimants.sort_unstable();
            claimants.dedup();
            let winners: Vec<usize> = claimants
                .iter()
                .copied()
                .filter(|&c| {
                    !claimants
                        .iter()
                        .any(|&o| o != c && hier.classes[c].ancestors.contains(&o))
                })
                .collect();
            if winners.len() == 1 && !icf_blocked.contains(&dtor_addr) {
                class_dtors.insert(dtor_addr, winners[0]);
            } else if winners.len() > 1 {
                icf_blocked.insert(dtor_addr);
            }
        }
    }

    // Step C: find all candidate functions referencing vftables (deterministic, no Listing required)
    // and classify constructors & non-virtual destructors.
    let mut vftable_owner: FxHashMap<u64, (usize, u32)> = FxHashMap::default();
    let mut vtable_slot_addrs: FxHashSet<u64> = FxHashSet::default();
    for (c, cls) in hier.classes.iter().enumerate() {
        for vf in &cls.vftables {
            vftable_owner.insert(vf.base, (c, vf.col.offset));
            for &s in &vf.slots {
                vtable_slot_addrs.insert(s);
            }
        }
    }
    for (&target, _) in &thunk_targets {
        vtable_slot_addrs.insert(target);
    }

    let mut all_entries: Vec<u64> = known_entries.to_vec();
    all_entries.extend(vtable_slot_addrs.iter().copied());
    all_entries.extend(class_dtors.keys().copied());
    if rk.is64 {
        for (begin, _) in crate::entry::pe64_pdata_extents(bytes) {
            all_entries.push(begin);
        }
    }
    all_entries.sort_unstable();
    all_entries.dedup();

    let pdata_ranges: Vec<(u64, u64)> = if rk.is64 {
        let mut r = crate::entry::pe64_pdata_extents(bytes);
        r.sort_unstable();
        r
    } else {
        Vec::new()
    };

    let candidates = find_vftable_referencing_functions(
        file,
        &rk,
        &vftable_owner,
        &pdata_ranges,
        &all_entries,
    );

    let mut class_ctors: BTreeMap<u64, usize> = BTreeMap::new();
    let mut func_vptr_owners: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for &entry in &candidates {
        if vtable_slot_addrs.contains(&entry)
            || thunks.contains_key(&entry)
            || deleting_dtors.contains_key(&entry)
            || icf_blocked.contains(&entry)
        {
            continue;
        }
        let end_bound = function_end_bound(entry, &pdata_ranges, &all_entries, &text);
        let walk = walker.walk_ctor_dtor(entry, end_bound, &vftable_owner, MAX_CTOR_INSNS);
        let Some(owner_cls) = classify_owner_from_vptr_stores(&walk.vptr_stores, &hier) else {
            continue;
        };
        func_vptr_owners.entry(entry).or_default().push(owner_cls);
        if class_dtors.contains_key(&entry) {
            continue;
        }
        if is_constructor_walk(&walk, owner_cls, &hier, &vftable_owner, &class_dtors) {
            class_ctors.insert(entry, owner_cls);
        } else if is_destructor_walk(&walk, owner_cls, &hier, &vftable_owner, &class_dtors) {
            class_dtors.insert(entry, owner_cls);
        }
    }

    // Build deterministic base-first topological order and remap class indices.
    let topo = hier.topological_order();
    let mut old_to_new: Vec<usize> = vec![0; hier.classes.len()];
    for (new_idx, &old_idx) in topo.iter().enumerate() {
        old_to_new[old_idx] = new_idx;
    }

    // Collect every method assigned to each class (with its entry `this` byte offset within C)
    // for cross-method member layout synthesis and symbol/method emission.
    let mut methods_for_layout: Vec<Vec<(u64, i64)>> = vec![Vec::new(); hier.classes.len()];
    let mut function_symbols: Vec<SymFact> = Vec::new();
    let mut method_facts: Vec<RecoveredMsvcMethod> = Vec::new();
    let mut emitted_method_addrs: FxHashSet<u64> = FxHashSet::default();
    let mut emitted_sym_addrs: FxHashSet<u64> = FxHashSet::default();

    // 1. Deleting destructors.
    for (&addr, &(cls_idx, is_vector, this_off, owner_override)) in &deleting_dtors {
        let cls_name = &hier.classes[cls_idx].name;
        let sym_name = if is_vector {
            format!("{cls_name}::vector_deleting_destructor")
        } else {
            format!("{cls_name}::scalar_deleting_destructor")
        };
        if emitted_sym_addrs.insert(addr) {
            function_symbols.push(SymFact {
                addr,
                name: sym_name.clone(),
                kind: SymKind::Function,
            });
        }
        let this_cls = owner_override.unwrap_or(cls_idx);
        if emitted_method_addrs.insert(addr) {
            method_facts.push(RecoveredMsvcMethod {
                addr,
                name: sym_name,
                this_class_idx: old_to_new[this_cls],
                kind: RecoveredMethodKind::DeletingDtor,
            });
        }
        if this_off >= 0 {
            methods_for_layout[cls_idx].push((addr, this_off));
        }
    }

    // 2. Non-deleting destructors (~C).
    for (&addr, &cls_idx) in &class_dtors {
        let cls_name = &hier.classes[cls_idx].name;
        let short = short_class_name(cls_name);
        let sym_name = format!("{cls_name}::~{short}");
        if emitted_sym_addrs.insert(addr) {
            function_symbols.push(SymFact {
                addr,
                name: sym_name.clone(),
                kind: SymKind::Function,
            });
        }
        if emitted_method_addrs.insert(addr) {
            method_facts.push(RecoveredMsvcMethod {
                addr,
                name: sym_name,
                this_class_idx: old_to_new[cls_idx],
                kind: RecoveredMethodKind::Dtor,
            });
        }
        methods_for_layout[cls_idx].push((addr, 0));
    }

    // 3. Constructors (C::C).
    for (&addr, &cls_idx) in &class_ctors {
        let cls_name = &hier.classes[cls_idx].name;
        let short = short_class_name(cls_name);
        let sym_name = format!("{cls_name}::{short}");
        if emitted_sym_addrs.insert(addr) {
            function_symbols.push(SymFact {
                addr,
                name: sym_name.clone(),
                kind: SymKind::Function,
            });
        }
        if emitted_method_addrs.insert(addr) {
            method_facts.push(RecoveredMsvcMethod {
                addr,
                name: sym_name,
                this_class_idx: old_to_new[cls_idx],
                kind: RecoveredMethodKind::Ctor,
            });
        }
        methods_for_layout[cls_idx].push((addr, 0));
    }

    // 4. Adjustor & vtordisp thunks + their target methods.
    for (&thunk_addr, &(cls_idx, vf_idx, slot_idx, kind)) in &thunks {
        let cls = &hier.classes[cls_idx];
        let vf = &cls.vftables[vf_idx];
        let base_cls_idx = vf.owner_base_idx.unwrap_or(cls_idx);
        let (target, thunk_suffix, target_this_cls, target_this_off) = match kind {
            ThunkKind::Adjustor { delta, target } => {
                let adj = delta.unsigned_abs();
                let stem = if let Some(&(_, is_vec, _, _)) = deleting_dtors.get(&target) {
                    if is_vec {
                        "vector_deleting_destructor".to_string()
                    } else {
                        "scalar_deleting_destructor".to_string()
                    }
                } else {
                    format!("vfunc_{slot_idx}")
                };
                let (t_cls, t_off) = if adj == vf.col.offset as u64 {
                    (cls_idx, 0i64)
                } else {
                    (base_cls_idx, (vf.col.offset as i64).saturating_sub(delta))
                };
                (target, format!("[thunk]:{stem}_adjustor_{adj}"), t_cls, t_off)
            }
            ThunkKind::VtorDisp { constant_delta, target } => {
                let stem = if let Some(&(_, is_vec, _, _)) = deleting_dtors.get(&target) {
                    if is_vec {
                        "vector_deleting_destructor".to_string()
                    } else {
                        "scalar_deleting_destructor".to_string()
                    }
                } else {
                    format!("vfunc_{slot_idx}")
                };
                let (t_cls, t_off) = if constant_delta != 0
                    && constant_delta.unsigned_abs() == vf.col.offset as u64
                {
                    (cls_idx, 0i64)
                } else {
                    (base_cls_idx, vf.col.offset as i64)
                };
                (target, format!("[thunk]:{stem}_vtordisp"), t_cls, t_off)
            }
        };
        let thunk_name = format!("{}::{thunk_suffix}", cls.name);
        if emitted_sym_addrs.insert(thunk_addr) {
            function_symbols.push(SymFact {
                addr: thunk_addr,
                name: thunk_name.clone(),
                kind: SymKind::Function,
            });
        }
        if emitted_method_addrs.insert(thunk_addr) {
            method_facts.push(RecoveredMsvcMethod {
                addr: thunk_addr,
                name: thunk_name,
                this_class_idx: old_to_new[base_cls_idx],
                kind: RecoveredMethodKind::AdjustorThunk,
            });
        }
        if !icf_blocked.contains(&target) && !deleting_dtors.contains_key(&target) {
            let target_name = format!("{}::vfunc_{slot_idx}", cls.name);
            if emitted_sym_addrs.insert(target) {
                function_symbols.push(SymFact {
                    addr: target,
                    name: target_name.clone(),
                    kind: SymKind::Function,
                });
            }
            if emitted_method_addrs.insert(target) {
                method_facts.push(RecoveredMsvcMethod {
                    addr: target,
                    name: target_name,
                    this_class_idx: old_to_new[target_this_cls],
                    kind: RecoveredMethodKind::VirtualMethod,
                });
            }
            methods_for_layout[cls_idx].push((target, target_this_off));
        }
    }

    // 5. Remaining uniquely attributed virtual methods (primary and direct secondary).
    for (&fn_addr, attr) in &slot_attr {
        let SlotAttribution::Unique { class_idx, vf_idx, slot_idx } = *attr else {
            continue;
        };
        if icf_blocked.contains(&fn_addr) || emitted_method_addrs.contains(&fn_addr) {
            continue;
        }
        let cls = &hier.classes[class_idx];
        let vf = &cls.vftables[vf_idx];
        let (this_cls, layout_off) = if vf.col.offset == 0 {
            (class_idx, 0i64)
        } else {
            (vf.owner_base_idx.unwrap_or(class_idx), vf.col.offset as i64)
        };
        let sym_name = if vf.col.offset == 0 {
            format!("{}::vfunc_{slot_idx}", cls.name)
        } else if let Some(bidx) = vf.owner_base_idx {
            format!("{}::vfunc_for_{}_{slot_idx}", cls.name, short_class_name(&hier.classes[bidx].name))
        } else {
            format!("{}::vfunc_{slot_idx}", cls.name)
        };
        if emitted_method_addrs.insert(fn_addr) {
            method_facts.push(RecoveredMsvcMethod {
                addr: fn_addr,
                name: sym_name,
                this_class_idx: old_to_new[this_cls],
                kind: RecoveredMethodKind::VirtualMethod,
            });
        }
        methods_for_layout[class_idx].push((fn_addr, layout_off));
    }

    // Step D: deterministic pre-decompile member layout synthesis in base-first topological order.
    let mut recovered_classes: Vec<RecoveredMsvcClass> = Vec::with_capacity(topo.len());
    for &old_idx in &topo {
        let cls = &hier.classes[old_idx];
        let mut method_list = methods_for_layout[old_idx].clone();
        method_list.sort_unstable();
        method_list.dedup();

        let mut raw_obs: BTreeMap<(u32, u32), FieldVote> = BTreeMap::new();
        for (m_addr, this_off) in method_list {
            let end_bound = function_end_bound(m_addr, &pdata_ranges, &all_entries, &text);
            walker.harvest_member_accesses(m_addr, end_bound, this_off, MAX_LAYOUT_INSNS, &mut raw_obs);
        }

        let vftables: Vec<RecoveredVfTableSpec> = cls
            .vftables
            .iter()
            .map(|vf| {
                let owner_new = vf.owner_base_idx.map(|b| old_to_new[b]);
                let slots = vf
                    .slots
                    .iter()
                    .enumerate()
                    .map(|(i, &target_addr)| {
                        let resolved = match thunks.get(&target_addr) {
                            Some(&(_, _, _, ThunkKind::Adjustor { target, .. }))
                            | Some(&(_, _, _, ThunkKind::VtorDisp { target, .. })) => target,
                            None => target_addr,
                        };
                        let is_del = deleting_dtors.contains_key(&resolved)
                            || deleting_dtors.contains_key(&target_addr);
                        let field_name = if is_del {
                            if deleting_dtors.get(&resolved).is_some_and(|d| d.1)
                                || deleting_dtors.get(&target_addr).is_some_and(|d| d.1)
                            {
                                "vector_deleting_destructor".to_string()
                            } else {
                                "scalar_deleting_destructor".to_string()
                            }
                        } else {
                            format!("vfunc_{i}")
                        };
                        RecoveredVfSlot {
                            target_addr,
                            field_name,
                            is_deleting_dtor: is_del,
                        }
                    })
                    .collect();
                RecoveredVfTableSpec {
                    base_addr: vf.base,
                    label: vf.label.clone(),
                    struct_name: vf.struct_name.clone(),
                    col_offset: vf.col.offset,
                    owner_class_idx: owner_new.or(Some(old_to_new[old_idx])),
                    slots,
                }
            })
            .collect();

        let known_size = known_sizes.get(&old_idx).copied();
        let (fields, size, align) = synthesize_class_layout(
            old_idx,
            &hier,
            &old_to_new,
            &recovered_classes,
            &vftables,
            &raw_obs,
            known_size,
            rk.ptr_size() as u32,
        );

        recovered_classes.push(RecoveredMsvcClass {
            name: cls.name.clone(),
            size,
            align,
            vftables,
            fields,
        });
    }

    out.msvc_classes = Some(MsvcClassRecoveryData {
        ptr_size: rk.ptr_size(),
        is_64: rk.is64,
        classes: recovered_classes,
        function_symbols,
        methods: method_facts,
    });
    out
}

#[derive(Clone, Copy, Debug, Default)]
struct FieldVote {
    count: u32,
    float_votes: u32,
    signed_votes: u32,
    ptr_votes: u32,
}

impl FieldVote {
    fn hint(&self, width: u32, ptr_size: u32) -> FieldTypeHint {
        if self.float_votes > 0 && (width == 4 || width == 8) {
            FieldTypeHint::Float
        } else if self.ptr_votes > 0 && width == ptr_size {
            FieldTypeHint::VoidPtr
        } else if self.signed_votes > 0 {
            FieldTypeHint::Int
        } else {
            FieldTypeHint::Uint
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn synthesize_class_layout(
    old_idx: usize,
    hier: &MsvcHierarchy,
    old_to_new: &[usize],
    completed: &[RecoveredMsvcClass],
    vftables: &[RecoveredVfTableSpec],
    raw_obs: &BTreeMap<(u32, u32), FieldVote>,
    known_size: Option<u32>,
    ptr_size: u32,
) -> (Vec<RecoveredClassField>, u32, u32) {
    let cls = &hier.classes[old_idx];
    let mut fields: Vec<RecoveredClassField> = Vec::new();
    let mut occupied: Vec<(u32, u32)> = Vec::new();
    let mut used_names: FxHashSet<String> = FxHashSet::default();

    let overlaps = |occ: &[(u32, u32)], start: u32, end: u32| -> bool {
        occ.iter().any(|&(a, b)| start < b && a < end)
    };
    let unique_name = |used: &mut FxHashSet<String>, base: String, off: u32| -> String {
        if used.insert(base.clone()) {
            base
        } else {
            let alt = format!("{base}_0x{off:x}");
            used.insert(alt.clone());
            alt
        }
    };

    // 1. Direct non-virtual base subobjects sorted by mdisp.
    let mut nv_bases: Vec<(u32, usize)> = cls
        .direct_bases
        .iter()
        .filter(|b| !b.is_virtual() && b.pmd.mdisp >= 0)
        .map(|b| (b.pmd.mdisp as u32, b.class_idx))
        .collect();
    nv_bases.sort_unstable();
    nv_bases.dedup();

    // Upper limits from virtual base vftables so a base with virtual bases never overlaps
    // the next base subobject or shared virtual base.
    let min_vbase_off: Option<u32> = cls
        .vftables
        .iter()
        .filter(|vf| vf.is_virtual_base && vf.col.offset > 0)
        .map(|vf| {
            if vf.col.cd_offset != 0 && vf.col.offset >= 4 {
                vf.col.offset - 4
            } else {
                vf.col.offset
            }
        })
        .min();

    for (i, &(mdisp, base_old_idx)) in nv_bases.iter().enumerate() {
        let base_new_idx = old_to_new[base_old_idx];
        let Some(base_cls) = completed.get(base_new_idx) else {
            continue;
        };
        let next_limit = nv_bases
            .get(i + 1)
            .map(|&(next_off, _)| next_off)
            .or(min_vbase_off)
            .unwrap_or(u32::MAX);
        let max_slot = next_limit.saturating_sub(mdisp);
        let bsize = base_cls.size;
        if bsize > 0 && bsize <= max_slot && !overlaps(&occupied, mdisp, mdisp + bsize) {
            let short = sanitize_ident(short_class_name(&base_cls.name));
            let fname = if mdisp == 0 {
                format!("base_{short}")
            } else {
                format!("base_{short}_0x{mdisp:x}")
            };
            let fname = unique_name(&mut used_names, fname, mdisp);
            fields.push(RecoveredClassField {
                offset: mdisp,
                name: fname,
                kind: RecoveredFieldKind::BaseSubobject { base_class_idx: base_new_idx },
            });
            occupied.push((mdisp, mdisp + bsize));
        } else if max_slot > 0 {
            // Base has virtual bases making its complete size exceed its non-virtual slice:
            // inline its non-virtual fields that fit inside `[mdisp, mdisp + max_slot)`.
            for bf in &base_cls.fields {
                if matches!(bf.kind, RecoveredFieldKind::VtorDisp) {
                    continue;
                }
                let fwidth = field_width(bf, completed, ptr_size);
                if bf.offset.saturating_add(fwidth) <= max_slot {
                    let abs_off = mdisp + bf.offset;
                    if !overlaps(&occupied, abs_off, abs_off + fwidth) {
                        let fname = unique_name(&mut used_names, bf.name.clone(), abs_off);
                        fields.push(RecoveredClassField {
                            offset: abs_off,
                            name: fname,
                            kind: bf.kind.clone(),
                        });
                        occupied.push((abs_off, abs_off + fwidth));
                    }
                }
            }
        }
    }

    // 2. Virtual base subobjects (placed at their COL offset if non-overlapping).
    for vf in &cls.vftables {
        if !vf.is_virtual_base || vf.col.offset == 0 {
            continue;
        }
        if vf.col.cd_offset != 0 && vf.col.offset >= 4 {
            let vt_off = vf.col.offset - 4;
            if !overlaps(&occupied, vt_off, vt_off + 4) {
                let suffix = vf
                    .owner_base_idx
                    .map(|b| sanitize_ident(short_class_name(&hier.classes[b].name)))
                    .unwrap_or_else(|| format!("0x{:x}", vf.col.offset));
                let fname = unique_name(&mut used_names, format!("vtordisp_{suffix}"), vt_off);
                fields.push(RecoveredClassField {
                    offset: vt_off,
                    name: fname,
                    kind: RecoveredFieldKind::VtorDisp,
                });
                occupied.push((vt_off, vt_off + 4));
            }
        }
        if let Some(base_old_idx) = vf.owner_base_idx {
            let base_new_idx = old_to_new[base_old_idx];
            if let Some(base_cls) = completed.get(base_new_idx) {
                let off = vf.col.offset;
                let bsize = base_cls.size;
                if bsize > 0 && !overlaps(&occupied, off, off + bsize) {
                    let short = sanitize_ident(short_class_name(&base_cls.name));
                    let fname = unique_name(&mut used_names, format!("vbase_{short}"), off);
                    fields.push(RecoveredClassField {
                        offset: off,
                        name: fname,
                        kind: RecoveredFieldKind::BaseSubobject { base_class_idx: base_new_idx },
                    });
                    occupied.push((off, off + bsize));
                }
            }
        }
    }

    // 3. Own vptr slots not already covered by an embedded base subobject.
    for vf in vftables {
        let off = vf.col_offset;
        if !overlaps(&occupied, off, off + ptr_size) {
            let base_name = if off == 0 {
                "vftable".to_string()
            } else {
                format!("vftable_0x{off:x}")
            };
            let fname = unique_name(&mut used_names, base_name, off);
            fields.push(RecoveredClassField {
                offset: off,
                name: fname,
                kind: RecoveredFieldKind::VftablePtr {
                    vftable_struct_name: vf.struct_name.clone(),
                },
            });
            occupied.push((off, off + ptr_size));
        }
    }

    // 4. `__vbptr` slots from virtual bases (`pmd.pdisp >= 0`).
    let mut pdisps: Vec<u32> = cls
        .all_bases
        .iter()
        .filter(|b| b.is_virtual())
        .map(|b| b.pmd.pdisp as u32)
        .collect();
    pdisps.sort_unstable();
    pdisps.dedup();
    for pdisp in pdisps {
        if !overlaps(&occupied, pdisp, pdisp + ptr_size) {
            let fname = unique_name(&mut used_names, "__vbptr".to_string(), pdisp);
            fields.push(RecoveredClassField {
                offset: pdisp,
                name: fname,
                kind: RecoveredFieldKind::Vbptr,
            });
            occupied.push((pdisp, pdisp + ptr_size));
        }
    }

    // 5. Reconcile synthesized member accesses into non-overlapping fields.
    // Drop coalesced wider accesses (e.g. 16-byte SIMD zero or 8-byte paired zero-store in a dtor)
    // when narrower aligned scalar accesses touch multiple sub-offsets or carry stronger type evidence.
    let mut candidates: Vec<(u32, u32, FieldVote)> = raw_obs
        .iter()
        .filter_map(|(&(off, width), &vote)| {
            if width == 0 || width > 16 {
                return None;
            }
            let end = off.checked_add(width)?;
            if width >= 8 {
                let mut sub_offsets = BTreeSet::new();
                let mut sub_votes = 0u32;
                let mut sub_typed = false;
                for (&(so, sw), sv) in raw_obs {
                    if sw < width && sw <= 8 && so >= off && so.saturating_add(sw) <= end {
                        let aligned = so % sw.min(ptr_size).max(1) == 0;
                        if aligned {
                            sub_offsets.insert(so);
                            sub_votes = sub_votes.saturating_add(sv.count);
                            if sv.float_votes > 0 || sv.signed_votes > 0 || sv.ptr_votes > 0 {
                                sub_typed = true;
                            }
                        }
                    }
                }
                if width == 16 && !sub_offsets.is_empty() {
                    return None;
                }
                if sub_offsets.len() >= 2 || (sub_typed && sub_votes >= vote.count) {
                    return None;
                }
            }
            if let Some(ks) = known_size {
                if end > ks {
                    return None;
                }
            }
            if overlaps(&occupied, off, end) {
                return None;
            }
            Some((off, width, vote))
        })
        .collect();

    // Rank: aligned first, then wider scalar (up to ptr_size), then higher vote count, then offset.
    candidates.sort_by(|a, b| {
        let a_aligned = a.0 % a.1.min(ptr_size).max(1) == 0;
        let b_aligned = b.0 % b.1.min(ptr_size).max(1) == 0;
        b_aligned
            .cmp(&a_aligned)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.2.count.cmp(&a.2.count))
            .then_with(|| a.0.cmp(&b.0))
    });

    for (off, width, vote) in candidates {
        let end = off + width;
        if overlaps(&occupied, off, end) {
            continue;
        }
        if width == 16 {
            // Split 16-byte unhinted bulk-zero into two 8-byte fields for clean C rendering.
            for sub in [0u32, 8u32] {
                let s_off = off + sub;
                let fname = unique_name(&mut used_names, format!("field_0x{s_off:x}"), s_off);
                fields.push(RecoveredClassField {
                    offset: s_off,
                    name: fname,
                    kind: RecoveredFieldKind::Primitive { width: 8, hint: FieldTypeHint::Uint },
                });
                occupied.push((s_off, s_off + 8));
            }
            continue;
        }
        let hint = vote.hint(width, ptr_size);
        let fname = unique_name(&mut used_names, format!("field_0x{off:x}"), off);
        fields.push(RecoveredClassField {
            offset: off,
            name: fname,
            kind: RecoveredFieldKind::Primitive { width, hint },
        });
        occupied.push((off, end));
    }

    fields.sort_by_key(|f| f.offset);

    let max_end = occupied.iter().map(|&(_, e)| e).max().unwrap_or(0);
    let mut align = 1u32;
    for f in &fields {
        let fa = match &f.kind {
            RecoveredFieldKind::VftablePtr { .. } | RecoveredFieldKind::Vbptr => ptr_size,
            RecoveredFieldKind::VtorDisp => 4,
            RecoveredFieldKind::BaseSubobject { base_class_idx } => {
                completed.get(*base_class_idx).map_or(ptr_size, |c| c.align)
            }
            RecoveredFieldKind::Primitive { width, .. } => (*width).min(ptr_size).max(1),
        };
        align = align.max(fa);
    }
    align = align.min(ptr_size).max(1);
    let raw_size = max_end.max(known_size.unwrap_or(0)).max(ptr_size);
    let size = (raw_size + align - 1) / align * align;
    (fields, size, align)
}

fn field_width(f: &RecoveredClassField, completed: &[RecoveredMsvcClass], ptr_size: u32) -> u32 {
    match &f.kind {
        RecoveredFieldKind::VftablePtr { .. } | RecoveredFieldKind::Vbptr => ptr_size,
        RecoveredFieldKind::VtorDisp => 4,
        RecoveredFieldKind::BaseSubobject { base_class_idx } => {
            completed.get(*base_class_idx).map_or(ptr_size, |c| c.size)
        }
        RecoveredFieldKind::Primitive { width, .. } => *width,
    }
}

fn sanitize_ident(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    let trimmed = clean.trim_matches('_');
    if trimmed.is_empty() {
        "class".to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Adjustor thunk & deleting destructor detection
// ---------------------------------------------------------------------------

fn decode_adjustor_thunk(
    walker: &MsvcWalker<'_>,
    text: &TextRanges,
    entry: u64,
) -> Option<ThunkKind> {
    let mut st = walker.initial_state();
    let mut at = entry;
    for _ in 0..MAX_THUNK_INSNS {
        let (ops, len) = walker.lift(at)?;
        for (opc, out, ins) in &ops {
            match opc {
                OpCode::CPUI_BRANCH => {
                    let target = ins.first().filter(|v| !is_constant(v))?.offset;
                    if target == entry || !text.contains(target) {
                        return None;
                    }
                    return match st.get_reg(walker.this_reg) {
                        Some(SymVal::This(delta)) if delta != 0 => {
                            Some(ThunkKind::Adjustor { delta: -delta, target })
                        }
                        Some(SymVal::VtorDispThis(const_delta)) => {
                            Some(ThunkKind::VtorDisp { constant_delta: -const_delta, target })
                        }
                        _ => None,
                    };
                }
                OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND | OpCode::CPUI_RETURN => return None,
                _ => walker.step(&mut st, *opc, out.as_ref(), ins, None),
            }
        }
        if len == 0 {
            break;
        }
        at = at.wrapping_add(len);
    }
    None
}

fn detect_purecall(
    file: &object::File<'_>,
    hier: &MsvcHierarchy,
    slot_attr: &BTreeMap<u64, SlotAttribution>,
    walker: &MsvcWalker<'_>,
) -> FxHashSet<u64> {
    let mut out = FxHashSet::default();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(name) = sym.name() {
            if name.contains("_purecall") && sym.address() != 0 {
                out.insert(sym.address());
            }
        }
    }
    // Repeated-slot heuristic: shared across >= 2 unrelated classes and very short with no `this` deref.
    for (&addr, attr) in slot_attr {
        let SlotAttribution::IcfShared { classes } = attr else {
            continue;
        };
        if classes.len() < 2 {
            continue;
        }
        let mut st = walker.initial_state();
        let mut at = addr;
        let mut reads_this = false;
        let mut has_call_or_trap = false;
        for _ in 0..12 {
            let Some((ops, len)) = walker.lift(at) else { break };
            let mut stop = false;
            for (opc, out_vn, ins) in &ops {
                match opc {
                    OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                        if matches!(
                            ins.get(1).and_then(|a| walker.eval(&st, a)),
                            Some(SymVal::This(_))
                        ) {
                            reads_this = true;
                        }
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER => {
                        has_call_or_trap = true;
                    }
                    OpCode::CPUI_RETURN | OpCode::CPUI_BRANCH => {
                        stop = true;
                    }
                    _ => walker.step(&mut st, *opc, out_vn.as_ref(), ins, None),
                }
            }
            if stop || len == 0 {
                break;
            }
            at = at.wrapping_add(len);
        }
        if !reads_this && has_call_or_trap {
            out.insert(addr);
        }
    }
    let _ = hier;
    out
}

#[derive(Clone, Debug)]
struct DeletingDtorProbe {
    tests_flag_1: bool,
    tests_flag_2: bool,
    returns_this: bool,
    /// `(callee, arg0_is_this, const_size_arg1)`
    conditional_calls: Vec<(u64, bool, Option<u32>)>,
    unconditional_calls: Vec<(u64, bool)>,
    stores_own_vptr: bool,
}

type DeletingDtorMap = BTreeMap<u64, (usize, bool, i64, Option<usize>)>;

fn detect_deleting_destructors(
    file: &object::File<'_>,
    hier: &MsvcHierarchy,
    slot_attr: &BTreeMap<u64, SlotAttribution>,
    thunks: &BTreeMap<u64, (usize, usize, usize, ThunkKind)>,
    icf_blocked: &FxHashSet<u64>,
    walker: &MsvcWalker<'_>,
    text: &TextRanges,
) -> (FxHashSet<u64>, DeletingDtorMap, Vec<(usize, u64)>, FxHashMap<usize, u32>) {
    let mut delete_addrs: FxHashSet<u64> = FxHashSet::default();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(name) = sym.name() {
            if is_delete_symbol_name(name) && sym.address() != 0 {
                delete_addrs.insert(sym.address());
            }
        }
    }

    // Build per-class vftable map for recognizing inlined dtor vptr stores.
    let mut class_vptrs: Vec<FxHashSet<u64>> = vec![FxHashSet::default(); hier.classes.len()];
    for (c, cls) in hier.classes.iter().enumerate() {
        for vf in &cls.vftables {
            class_vptrs[c].insert(vf.base);
        }
    }

    // Collect slot-0 candidates (both primary vftable slot 0 and secondary/virtual-base
    // slot 0 thunk targets when the class has no primary vftable).
    // Tuple: `(fn_addr, cls_idx, this_offset_in_cls, owner_override_for_this)`
    let mut slot0_candidates: Vec<(u64, usize, i64, Option<usize>)> = Vec::new();
    let mut seen_cand: FxHashSet<(u64, usize)> = FxHashSet::default();

    for (c, cls) in hier.classes.iter().enumerate() {
        for vf in &cls.vftables {
            let Some(&slot0) = vf.slots.first() else {
                continue;
            };
            if let Some(&(_, _, _, kind)) = thunks.get(&slot0) {
                let (target, this_off, owner_ov) = match kind {
                    ThunkKind::Adjustor { delta, target } => {
                        if delta.unsigned_abs() == vf.col.offset as u64 {
                            (target, 0i64, None)
                        } else {
                            (target, vf.col.offset as i64 - delta, vf.owner_base_idx)
                        }
                    }
                    ThunkKind::VtorDisp { constant_delta, target } => {
                        if constant_delta != 0 && constant_delta.unsigned_abs() == vf.col.offset as u64 {
                            (target, 0i64, None)
                        } else {
                            (target, vf.col.offset as i64, vf.owner_base_idx)
                        }
                    }
                };
                if !icf_blocked.contains(&target) && seen_cand.insert((target, c)) {
                    slot0_candidates.push((target, c, this_off, owner_ov));
                }
            } else if vf.col.offset == 0 {
                if let Some(SlotAttribution::Unique { class_idx, .. }) = slot_attr.get(&slot0) {
                    if *class_idx == c && !icf_blocked.contains(&slot0) && seen_cand.insert((slot0, c)) {
                        slot0_candidates.push((slot0, c, 0, None));
                    }
                }
            }
        }
    }

    let mut probes: Vec<((u64, usize, i64, Option<usize>), DeletingDtorProbe)> = Vec::new();
    let mut cond_callee_classes: FxHashMap<u64, FxHashSet<usize>> = FxHashMap::default();
    for cand in slot0_candidates {
        let probe = walker.probe_deleting_dtor(cand.0, &class_vptrs[cand.1], text, MAX_DTOR_INSNS);
        if (probe.tests_flag_1 || probe.tests_flag_2) && probe.returns_this {
            for &(callee, arg0_is_this, _) in &probe.conditional_calls {
                if arg0_is_this {
                    cond_callee_classes.entry(callee).or_default().insert(cand.1);
                }
            }
        }
        probes.push((cand, probe));
    }

    // 2-call common-callee fallback: a function called conditionally on `(flags & 1)` with
    // `this` across >= 2 distinct classes' slot-0 methods is `operator delete`!
    for (callee, cls_set) in cond_callee_classes {
        if cls_set.len() >= 2 {
            delete_addrs.insert(callee);
        }
    }

    let mut deleting_dtors: DeletingDtorMap = BTreeMap::new();
    let mut inner_dtors: Vec<(usize, u64)> = Vec::new();
    let mut known_sizes: FxHashMap<usize, u32> = FxHashMap::default();

    for ((addr, cls_idx, this_off, owner_ov), probe) in probes {
        if !(probe.tests_flag_1 || probe.tests_flag_2) || !probe.returns_this {
            continue;
        }
        let del_call = probe
            .conditional_calls
            .iter()
            .find(|&&(callee, arg0_is_this, _)| arg0_is_this && delete_addrs.contains(&callee));
        let Some(&(_, _, opt_size)) = del_call else {
            continue;
        };
        let has_dtor_work = probe.stores_own_vptr
            || probe
                .unconditional_calls
                .iter()
                .any(|&(c, is_this)| is_this && !delete_addrs.contains(&c));
        if !has_dtor_work {
            continue;
        }
        // If another class already claimed this deleting dtor, prefer the entry with this_off == 0.
        let entry = deleting_dtors
            .entry(addr)
            .or_insert((cls_idx, probe.tests_flag_2 && !probe.tests_flag_1, this_off, owner_ov));
        if entry.2 != 0 && this_off == 0 {
            *entry = (cls_idx, probe.tests_flag_2 && !probe.tests_flag_1, this_off, owner_ov);
        }
        if let Some(sz) = opt_size {
            if sz >= 4 && sz <= MAX_MEMBER_OFFSET {
                known_sizes.entry(cls_idx).or_insert(sz);
            }
        }
        // Extract inner non-deleting destructor `C::~C` (first unconditional call passed `this`).
        if let Some(&(inner, _)) = probe
            .unconditional_calls
            .iter()
            .find(|&&(callee, is_this)| is_this && !delete_addrs.contains(&callee))
        {
            inner_dtors.push((cls_idx, inner));
        }
    }

    (delete_addrs, deleting_dtors, inner_dtors, known_sizes)
}

fn is_delete_symbol_name(name: &str) -> bool {
    name.starts_with("??3@")
        || name.starts_with("??_V@")
        || matches!(name, "free" | "_free" | "j_free" | "operator delete" | "operator delete[]")
}

// ---------------------------------------------------------------------------
// Deterministic vftable-reference scanner (works without Listing!)
// ---------------------------------------------------------------------------

fn find_vftable_referencing_functions(
    file: &object::File<'_>,
    rk: &RefKind,
    vftable_owner: &FxHashMap<u64, (usize, u32)>,
    pdata_ranges: &[(u64, u64)],
    sorted_entries: &[u64],
) -> Vec<u64> {
    let mut hit_addrs: Vec<u64> = Vec::new();
    let mut call_targets: Vec<u64> = Vec::new();
    let mut exec_spans: Vec<(u64, &[u8])> = Vec::new();

    for sec in file.sections() {
        let exec = sec.kind() == object::SectionKind::Text
            || matches!(
                sec.flags(),
                object::SectionFlags::Coff { characteristics }
                    if characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0
            );
        if !exec {
            continue;
        }
        let Ok(data) = sec.data() else { continue };
        let base = sec.address();
        if base == 0 || data.len() < 7 {
            continue;
        }
        exec_spans.push((base, data));
        if rk.is64 {
            // Scan for x64 RIP-relative LEA and direct E8 CALL targets (catches leaf ctors in .pdata gaps).
            let mut i = 0usize;
            while i < data.len() {
                if i + 7 <= data.len()
                    && (data[i] == 0x48 || data[i] == 0x4C)
                    && data[i + 1] == 0x8D
                    && (data[i + 2] & 0xC7) == 0x05
                {
                    let disp = i32::from_le_bytes([
                        data[i + 3],
                        data[i + 4],
                        data[i + 5],
                        data[i + 6],
                    ]) as i64;
                    let rip_after = base + (i as u64) + 7;
                    let target = rip_after.wrapping_add(disp as u64);
                    if vftable_owner.contains_key(&target) {
                        hit_addrs.push(base + i as u64);
                    }
                } else if i + 5 <= data.len() && data[i] == 0xE8 {
                    let disp = i32::from_le_bytes([
                        data[i + 1],
                        data[i + 2],
                        data[i + 3],
                        data[i + 4],
                    ]) as i64;
                    let target = (base + (i as u64) + 5).wrapping_add(disp as u64);
                    if target >= base && target < base + data.len() as u64 {
                        let off = (target - base) as usize;
                        let aligned_or_padded = (target & 0xf) == 0
                            || (off > 0 && matches!(data[off - 1], 0xCC | 0xC3 | 0x90));
                        if aligned_or_padded {
                            call_targets.push(target);
                        }
                    }
                }
                i += 1;
            }
        } else {
            // x86 PE32: scan for 4-byte immediate VA matching a vftable address + E8 call targets.
            let mut i = 0usize;
            while i + 4 <= data.len() {
                let imm = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as u64;
                if vftable_owner.contains_key(&imm) {
                    hit_addrs.push(base + i as u64);
                }
                if i + 5 <= data.len() && data[i] == 0xE8 {
                    let disp = i32::from_le_bytes([
                        data[i + 1],
                        data[i + 2],
                        data[i + 3],
                        data[i + 4],
                    ]) as i64;
                    let target = (base + (i as u64) + 5).wrapping_add(disp as u64);
                    if target >= base && target < base + data.len() as u64 {
                        let off = (target - base) as usize;
                        if (target & 0xf) == 0
                            || (off > 0 && matches!(data[off - 1], 0xCC | 0xC3 | 0x90))
                        {
                            call_targets.push(target);
                        }
                    }
                }
                i += 1;
            }
        }
    }

    let mut entries = sorted_entries.to_vec();
    for target in call_targets {
        // Reject targets strictly inside an existing .pdata function body.
        let inside_pdata = if !pdata_ranges.is_empty() {
            let idx = pdata_ranges.partition_point(|&(s, _)| s <= target);
            idx > 0 && target > pdata_ranges[idx - 1].0 && target < pdata_ranges[idx - 1].1
        } else {
            false
        };
        if !inside_pdata {
            entries.push(target);
        }
    }
    entries.sort_unstable();
    entries.dedup();

    let mut funcs: BTreeSet<u64> = BTreeSet::new();
    for hit in hit_addrs {
        if let Some(entry) = enclosing_function(hit, pdata_ranges, &entries, &exec_spans) {
            funcs.insert(entry);
        }
    }
    funcs.into_iter().collect()
}

fn enclosing_function(
    addr: u64,
    pdata_ranges: &[(u64, u64)],
    sorted_entries: &[u64],
    exec_spans: &[(u64, &[u8])],
) -> Option<u64> {
    let mut gap_floor: u64 = 0;
    if !pdata_ranges.is_empty() {
        let idx = pdata_ranges.partition_point(|&(start, _)| start <= addr);
        if idx > 0 {
            let (start, end) = pdata_ranges[idx - 1];
            if addr >= start && addr < end {
                return Some(start);
            }
            // `addr` lies PAST the end of the preceding .pdata range (a leaf function gap).
            gap_floor = end;
        }
    }
    let idx = sorted_entries.partition_point(|&e| e <= addr);
    if idx > 0 {
        let start = sorted_entries[idx - 1];
        if start >= gap_floor && addr.saturating_sub(start) <= 0x4000 {
            return Some(start);
        }
    }
    // Fallback for an uncalled leaf function in a .pdata gap: skip 0xCC/0x90 padding from `gap_floor`.
    if gap_floor != 0 && addr >= gap_floor && addr - gap_floor <= 0x200 {
        for &(base, data) in exec_spans {
            if gap_floor >= base && addr < base + data.len() as u64 {
                let mut cur = (gap_floor - base) as usize;
                let limit = (addr - base) as usize;
                while cur < limit && matches!(data[cur], 0xCC | 0x90) {
                    cur += 1;
                }
                return Some(base + cur as u64);
            }
        }
    }
    None
}

fn function_end_bound(
    entry: u64,
    pdata_ranges: &[(u64, u64)],
    sorted_entries: &[u64],
    text: &TextRanges,
) -> u64 {
    if !pdata_ranges.is_empty() {
        if let Ok(i) = pdata_ranges.binary_search_by_key(&entry, |&(s, _)| s) {
            return pdata_ranges[i].1;
        }
    }
    let idx = sorted_entries.partition_point(|&e| e <= entry);
    if let Some(&next) = sorted_entries.get(idx) {
        if next > entry && next - entry <= 0x8000 {
            return next;
        }
    }
    let _ = text;
    entry.saturating_add(0x4000)
}

// ---------------------------------------------------------------------------
// Constructor vs Destructor classification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct VptrStoreEvent {
    vptr: u64,
    offset: Option<i64>,
    step: usize,
}

#[derive(Clone, Debug)]
struct CallEvent {
    target: u64,
    step: usize,
}

#[derive(Clone, Debug, Default)]
struct CtorDtorWalk {
    vptr_stores: Vec<VptrStoreEvent>,
    calls: Vec<CallEvent>,
    returns_this: bool,
}

fn classify_owner_from_vptr_stores(
    stores: &[VptrStoreEvent],
    hier: &MsvcHierarchy,
) -> Option<usize> {
    if stores.is_empty() {
        return None;
    }
    let mut vft_to_cls: FxHashMap<u64, (usize, u32)> = FxHashMap::default();
    for (c, cls) in hier.classes.iter().enumerate() {
        for vf in &cls.vftables {
            vft_to_cls.insert(vf.base, (c, vf.col.offset));
        }
    }
    // Primary offset-0 stores and virtual-base indirect stores (`offset == None`) define the class.
    let mut primary_classes: Vec<usize> = Vec::new();
    for st in stores {
        let Some(&(cls, vf_off)) = vft_to_cls.get(&st.vptr) else {
            continue;
        };
        if st.offset == Some(0) || (st.offset.is_none() && vf_off > 0) {
            primary_classes.push(cls);
        }
    }
    if primary_classes.is_empty() {
        return None;
    }
    primary_classes.sort_unstable();
    primary_classes.dedup();
    // Pick the most-derived class if every other class in `primary_classes` is its ancestor.
    let most_derived = primary_classes
        .iter()
        .copied()
        .find(|&m| {
            primary_classes
                .iter()
                .all(|&other| other == m || hier.classes[m].ancestors.contains(&other))
        })?;
    Some(most_derived)
}

fn is_constructor_walk(
    walk: &CtorDtorWalk,
    owner_cls: usize,
    hier: &MsvcHierarchy,
    vftable_owner: &FxHashMap<u64, (usize, u32)>,
    known_dtors: &BTreeMap<u64, usize>,
) -> bool {
    if walk.returns_this {
        return true;
    }
    let own_first_step = walk
        .vptr_stores
        .iter()
        .filter(|s| vftable_owner.get(&s.vptr).is_some_and(|&(c, _)| c == owner_cls))
        .map(|s| s.step)
        .min();
    let Some(own_step) = own_first_step else {
        return false;
    };
    let anc_vptr_before = walk.vptr_stores.iter().any(|s| {
        s.step < own_step
            && vftable_owner
                .get(&s.vptr)
                .is_some_and(|&(c, _)| hier.classes[owner_cls].ancestors.contains(&c))
    });
    let calls_known_dtor_after = walk
        .calls
        .iter()
        .any(|c| c.step > own_step && known_dtors.contains_key(&c.target));
    anc_vptr_before && !calls_known_dtor_after
}

fn is_destructor_walk(
    walk: &CtorDtorWalk,
    owner_cls: usize,
    hier: &MsvcHierarchy,
    vftable_owner: &FxHashMap<u64, (usize, u32)>,
    known_dtors: &BTreeMap<u64, usize>,
) -> bool {
    if walk.returns_this {
        return false;
    }
    let own_first_step = walk
        .vptr_stores
        .iter()
        .filter(|s| vftable_owner.get(&s.vptr).is_some_and(|&(c, _)| c == owner_cls))
        .map(|s| s.step)
        .min();
    let Some(own_step) = own_first_step else {
        return false;
    };
    // Destructor writes its own vptr first, then destroys bases (vptr store or call to base dtor).
    let anc_vptr_after = walk.vptr_stores.iter().any(|s| {
        s.step > own_step
            && vftable_owner
                .get(&s.vptr)
                .is_some_and(|&(c, _)| hier.classes[owner_cls].ancestors.contains(&c))
    });
    let calls_base_dtor_after = walk.calls.iter().any(|c| {
        c.step > own_step
            && known_dtors
                .get(&c.target)
                .is_some_and(|&d_cls| hier.classes[owner_cls].ancestors.contains(&d_cls))
    });
    // Leaf class with no bases whose function writes its vptr and does NOT return `this`:
    // only accept as destructor if it has no `this`-returning path and stores its own vptr
    // before any call (avoids misclassifying random void helper methods).
    anc_vptr_after || calls_base_dtor_after
}

// ---------------------------------------------------------------------------
// Bounded multi-block symbolic SLEIGH p-code walker
// ---------------------------------------------------------------------------

type Key = (u32, u64, u32);
type Ops = Vec<(OpCode, Option<VarnodeData>, Vec<VarnodeData>)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymVal {
    This(i64),
    ThisLoad(i64),
    VtorDispThis(i64),
    VbaseDisp(i64, i64),
    VbaseAddr(i64, i64, i64),
    Frame(i64),
    Arg1,
    Arg1Bit(u64),
    Const(u64),
}

#[derive(Clone, Default)]
struct SymState {
    regs: FxHashMap<Key, SymVal>,
    frame: FxHashMap<(i64, u32), SymVal>,
}

impl SymState {
    fn get_reg(&self, key: Key) -> Option<SymVal> {
        if let Some(&v) = self.regs.get(&key) {
            return Some(v);
        }
        // Support reading sub-register (e.g. BL/EBX after mov ebx, edx) sharing `(space, offset)`.
        for (&(sp, off, sz), &v) in &self.regs {
            if sp == key.0 && off == key.1 && sz >= key.2 {
                if matches!(v, SymVal::Arg1 | SymVal::Arg1Bit(_) | SymVal::Const(_)) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn set_reg(&mut self, key: Key, val: Option<SymVal>) {
        let end = key.1.saturating_add(u64::from(key.2));
        self.regs.retain(|&(sp, off, sz), _| {
            sp != key.0 || off.saturating_add(u64::from(sz)) <= key.1 || end <= off
        });
        if let Some(v) = val {
            self.regs.insert(key, v);
        }
    }
}

struct MsvcWalker<'a> {
    arch: &'a Architecture,
    translate: &'a dyn Translate,
    code_space: Rc<kuna_base::space::AddrSpace>,
    ptr_size: u32,
    this_reg: Key,
    arg1_reg: Option<Key>,
    ret_reg: Key,
    sp_reg: Key,
    extrapop: i64,
}

impl<'a> MsvcWalker<'a> {
    fn new(arch: &'a Architecture, translate: &'a dyn Translate, rk: &RefKind) -> Option<Self> {
        let code_space = Rc::clone(arch.manage().get_default_code_space()?);
        let reg = |name: &str| -> Option<Key> {
            let vn = arch.get_register_varnode(name.as_bytes()).ok()?;
            key_of(&vn)
        };
        let (this_reg, arg1_reg, ret_reg, sp_reg) = if rk.is64 {
            (reg("RCX")?, Some(reg("RDX")?), reg("RAX")?, reg("RSP")?)
        } else {
            (reg("ECX")?, None, reg("EAX")?, reg("ESP")?)
        };
        let extrapop = arch
            .default_fp()
            .map(|m| m.get_extra_pop())
            .filter(|&p| p != EXTRAPOP_UNKNOWN)
            .map(i64::from)
            .unwrap_or(rk.ptr_size() as i64);
        Some(MsvcWalker {
            arch,
            translate,
            code_space,
            ptr_size: rk.ptr_size() as u32,
            this_reg,
            arg1_reg,
            ret_reg,
            sp_reg,
            extrapop,
        })
    }

    fn initial_state(&self) -> SymState {
        let mut st = SymState::default();
        st.regs.insert(self.this_reg, SymVal::This(0));
        st.regs.insert(self.sp_reg, SymVal::Frame(0));
        if let Some(a1) = self.arg1_reg {
            st.regs.insert(a1, SymVal::Arg1);
        } else {
            // x86 __thiscall: 1st stack arg at [ESP + 4].
            st.frame.insert((4, 4), SymVal::Arg1);
        }
        st
    }

    fn lift(&self, vma: u64) -> Option<(Ops, u64)> {
        let mut l = Lifted { ops: Vec::new() };
        let len = self
            .translate
            .one_instruction(&mut l, &Address::new(Rc::clone(&self.code_space), vma))
            .ok()?;
        Some((l.ops, u64::try_from(len).ok()?))
    }

    fn after_call(&self, st: &mut SymState) {
        let sp = st.regs.get(&self.sp_reg).copied();
        if let Some(model) = self.arch.default_fp() {
            st.regs.retain(|&(space, off, size), _| {
                let Some(spc) = self.arch.manage().get_space(space as i32) else {
                    return false;
                };
                let addr = Address::new(Rc::clone(spc), off);
                model.has_effect(&addr, size as i32) == effect_type::UNAFFECTED
            });
        } else {
            st.regs.clear();
        }
        if let Some(SymVal::Frame(o)) = sp {
            st.regs.insert(self.sp_reg, SymVal::Frame(o + self.extrapop));
        }
    }

    fn eval(&self, st: &SymState, vn: &VarnodeData) -> Option<SymVal> {
        if is_constant(vn) {
            return Some(SymVal::Const(vn.offset));
        }
        st.get_reg(key_of(vn)?)
    }

    fn step(
        &self,
        st: &mut SymState,
        opc: OpCode,
        out: Option<&VarnodeData>,
        ins: &[VarnodeData],
        mut on_load: Option<&mut dyn FnMut(i64, u32, Option<&VarnodeData>)>,
    ) {
        let val = match opc {
            OpCode::CPUI_COPY | OpCode::CPUI_SUBPIECE | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                ins.first().and_then(|v| self.eval(st, v))
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD => self.eval_add_sub(st, ins, false),
            OpCode::CPUI_INT_SUB => self.eval_add_sub(st, ins, true),
            OpCode::CPUI_INT_MULT => {
                let a = ins.first().and_then(|v| self.eval(st, v));
                let b = ins.get(1).and_then(|v| self.eval(st, v));
                match (a, b) {
                    (Some(v), Some(SymVal::Const(1))) | (Some(SymVal::Const(1)), Some(v)) => Some(v),
                    (Some(SymVal::Const(x)), Some(SymVal::Const(y))) => {
                        Some(SymVal::Const(x.wrapping_mul(y)))
                    }
                    _ => None,
                }
            }
            OpCode::CPUI_INT_AND => {
                let a = ins.first().and_then(|v| self.eval(st, v));
                let b = ins.get(1).and_then(|v| self.eval(st, v));
                match (a, b) {
                    (Some(SymVal::Arg1), Some(SymVal::Const(m)))
                    | (Some(SymVal::Const(m)), Some(SymVal::Arg1)) => Some(SymVal::Arg1Bit(m)),
                    (Some(SymVal::Arg1Bit(m1)), Some(SymVal::Const(m2)))
                    | (Some(SymVal::Const(m2)), Some(SymVal::Arg1Bit(m1))) => {
                        Some(SymVal::Arg1Bit(m1 & m2))
                    }
                    _ => None,
                }
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                let a = ins.first().and_then(|v| self.eval(st, v));
                let b = ins.get(1).and_then(|v| self.eval(st, v));
                match (a, b) {
                    (Some(SymVal::Arg1Bit(m)), Some(SymVal::Const(0)))
                    | (Some(SymVal::Const(0)), Some(SymVal::Arg1Bit(m))) => Some(SymVal::Arg1Bit(m)),
                    _ => None,
                }
            }
            OpCode::CPUI_BOOL_NEGATE => match ins.first().and_then(|v| self.eval(st, v)) {
                Some(SymVal::Arg1Bit(m)) => Some(SymVal::Arg1Bit(m)),
                _ => None,
            },
            OpCode::CPUI_LOAD => match ins.get(1).and_then(|a| self.eval(st, a)) {
                Some(SymVal::Frame(o)) => {
                    let sz = out.map_or(0, |o| o.size);
                    st.frame.get(&(o, sz)).copied()
                }
                Some(SymVal::This(o)) => {
                    if let Some(cb) = on_load.as_mut() {
                        if let Some(o_vn) = out {
                            cb(o, o_vn.size, Some(o_vn));
                        }
                    }
                    Some(SymVal::ThisLoad(o))
                }
                Some(SymVal::ThisLoad(pdisp)) => Some(SymVal::VbaseDisp(pdisp, 0)),
                Some(SymVal::VbaseDisp(pdisp, vdisp)) => Some(SymVal::VbaseDisp(pdisp, vdisp)),
                _ => None,
            },
            _ => None,
        };
        if opc == OpCode::CPUI_STORE {
            if let (Some(addr_vn), Some(val_vn)) = (ins.get(1), ins.get(2)) {
                let stored = self.eval(st, val_vn);
                if let Some(SymVal::Frame(o)) = self.eval(st, addr_vn) {
                    let size = val_vn.size;
                    st.frame.retain(|&(fo, fs), _| {
                        fo + i64::from(fs) <= o || o + i64::from(size) <= fo
                    });
                    if let Some(v) = stored {
                        st.frame.insert((o, size), v);
                    }
                }
            }
            return;
        }
        if let Some(out_vn) = out {
            if let Some(k) = key_of(out_vn) {
                st.set_reg(k, val);
            }
        }
    }

    fn eval_add_sub(&self, st: &SymState, ins: &[VarnodeData], sub: bool) -> Option<SymVal> {
        let a = self.eval(st, ins.first()?)?;
        let b = self.eval(st, ins.get(1)?)?;
        let bits = ins[0].size.saturating_mul(8).min(64);
        let delta = |c: u64| {
            let d = sign_extend(c, bits);
            if sub { d.wrapping_neg() } else { d }
        };
        match (a, b) {
            (SymVal::Const(x), SymVal::Const(y)) => {
                let r = if sub { x.wrapping_sub(y) } else { x.wrapping_add(y) };
                Some(SymVal::Const(truncate(r, bits)))
            }
            (SymVal::This(o), SymVal::Const(c)) => Some(SymVal::This(o.wrapping_add(delta(c)))),
            (SymVal::Const(c), SymVal::This(o)) if !sub => {
                Some(SymVal::This(o.wrapping_add(delta(c))))
            }
            (SymVal::Frame(o), SymVal::Const(c)) => Some(SymVal::Frame(o.wrapping_add(delta(c)))),
            (SymVal::Const(c), SymVal::Frame(o)) if !sub => {
                Some(SymVal::Frame(o.wrapping_add(delta(c))))
            }
            // vtordisp: `sub rcx, [rcx - 4]`
            (SymVal::This(o), SymVal::ThisLoad(-4)) if sub => Some(SymVal::VtorDispThis(o)),
            (SymVal::VtorDispThis(o), SymVal::Const(c)) => {
                Some(SymVal::VtorDispThis(o.wrapping_add(delta(c))))
            }
            // vbtable lookup: `vbptr + vdisp` -> `VbaseDisp(pdisp, vdisp)`
            (SymVal::ThisLoad(pdisp), SymVal::Const(c)) => {
                Some(SymVal::VbaseDisp(pdisp, delta(c)))
            }
            (SymVal::Const(c), SymVal::ThisLoad(pdisp)) if !sub => {
                Some(SymVal::VbaseDisp(pdisp, delta(c)))
            }
            // `this + vbtable[vdisp]` -> `VbaseAddr(pdisp, vdisp, o)`
            (SymVal::This(o), SymVal::VbaseDisp(p, v))
            | (SymVal::VbaseDisp(p, v), SymVal::This(o))
                if !sub =>
            {
                Some(SymVal::VbaseAddr(p, v, o))
            }
            (SymVal::VbaseAddr(p, v, o), SymVal::Const(c)) => {
                Some(SymVal::VbaseAddr(p, v, o.wrapping_add(delta(c))))
            }
            _ => None,
        }
    }

    fn probe_deleting_dtor(
        &self,
        entry: u64,
        own_vptrs: &FxHashSet<u64>,
        text: &TextRanges,
        max_insns: usize,
    ) -> DeletingDtorProbe {
        let mut probe = DeletingDtorProbe {
            tests_flag_1: false,
            tests_flag_2: false,
            returns_this: false,
            conditional_calls: Vec::new(),
            unconditional_calls: Vec::new(),
            stores_own_vptr: false,
        };
        let mut queue: VecDeque<(u64, SymState, bool)> = VecDeque::new();
        queue.push_back((entry, self.initial_state(), false));
        let mut visited: FxHashSet<(u64, bool)> = FxHashSet::default();
        let mut decoded = 0usize;

        while let Some((mut at, mut st, mut in_flag_branch)) = queue.pop_front() {
            if !visited.insert((at, in_flag_branch)) {
                continue;
            }
            while decoded < max_insns {
                decoded += 1;
                let Some((ops, len)) = self.lift(at) else { break };
                let mut stop = false;
                for (opc, out, ins) in &ops {
                    match opc {
                        OpCode::CPUI_CBRANCH => {
                            let cond_val = ins.get(1).and_then(|v| self.eval(&st, v));
                            let is_flag_branch = match cond_val {
                                Some(SymVal::Arg1Bit(m)) if m & 1 != 0 => {
                                    probe.tests_flag_1 = true;
                                    true
                                }
                                Some(SymVal::Arg1Bit(m)) if m & 2 != 0 => {
                                    probe.tests_flag_2 = true;
                                    true
                                }
                                _ => false,
                            };
                            if let Some(target_vn) = ins.first().filter(|v| !is_constant(v)) {
                                if text.contains(target_vn.offset) {
                                    queue.push_back((
                                        target_vn.offset,
                                        st.clone(),
                                        in_flag_branch || is_flag_branch,
                                    ));
                                }
                            }
                            if is_flag_branch {
                                in_flag_branch = true;
                            }
                        }
                        OpCode::CPUI_BRANCH => {
                            if let Some(target_vn) = ins.first().filter(|v| !is_constant(v)) {
                                if text.contains(target_vn.offset) {
                                    // Could be a tail call (e.g. `jmp operator delete`) or local jump.
                                    let arg0_is_this =
                                        matches!(st.get_reg(self.this_reg), Some(SymVal::This(_)));
                                    let size_arg = self.arg1_reg.and_then(|r| {
                                        if let Some(SymVal::Const(c)) = st.get_reg(r) {
                                            u32::try_from(c).ok()
                                        } else {
                                            None
                                        }
                                    });
                                    if target_vn.offset < entry
                                        || target_vn.offset > entry.saturating_add(0x200)
                                    {
                                        if in_flag_branch {
                                            probe.conditional_calls.push((
                                                target_vn.offset,
                                                arg0_is_this,
                                                size_arg,
                                            ));
                                        } else {
                                            probe
                                                .unconditional_calls
                                                .push((target_vn.offset, arg0_is_this));
                                        }
                                    } else {
                                        queue.push_back((target_vn.offset, st.clone(), in_flag_branch));
                                    }
                                }
                            }
                            stop = true;
                        }
                        OpCode::CPUI_CALL => {
                            if let Some(target_vn) = ins.first().filter(|v| !is_constant(v)) {
                                let arg0_is_this =
                                    matches!(st.get_reg(self.this_reg), Some(SymVal::This(_)));
                                let size_arg = self.arg1_reg.and_then(|r| {
                                    if let Some(SymVal::Const(c)) = st.get_reg(r) {
                                        u32::try_from(c).ok()
                                    } else {
                                        None
                                    }
                                });
                                if in_flag_branch {
                                    probe.conditional_calls.push((
                                        target_vn.offset,
                                        arg0_is_this,
                                        size_arg,
                                    ));
                                } else {
                                    probe
                                        .unconditional_calls
                                        .push((target_vn.offset, arg0_is_this));
                                }
                            }
                            self.after_call(&mut st);
                        }
                        OpCode::CPUI_CALLIND => {
                            if let Some(SymVal::Const(t)) =
                                ins.first().and_then(|v| self.eval(&st, v))
                            {
                                let arg0_is_this =
                                    matches!(st.get_reg(self.this_reg), Some(SymVal::This(_)));
                                if in_flag_branch {
                                    probe.conditional_calls.push((t, arg0_is_this, None));
                                } else {
                                    probe.unconditional_calls.push((t, arg0_is_this));
                                }
                            }
                            self.after_call(&mut st);
                        }
                        OpCode::CPUI_RETURN => {
                            if matches!(st.get_reg(self.ret_reg), Some(SymVal::This(_))) {
                                probe.returns_this = true;
                            }
                            stop = true;
                        }
                        OpCode::CPUI_STORE => {
                            if let (Some(addr_vn), Some(val_vn)) = (ins.get(1), ins.get(2)) {
                                if matches!(
                                    self.eval(&st, addr_vn),
                                    Some(SymVal::This(_) | SymVal::VbaseAddr(..))
                                ) {
                                    if let Some(SymVal::Const(v)) = self.eval(&st, val_vn) {
                                        if own_vptrs.contains(&v) {
                                            probe.stores_own_vptr = true;
                                        }
                                    }
                                }
                            }
                            self.step(&mut st, *opc, out.as_ref(), ins, None);
                        }
                        _ => self.step(&mut st, *opc, out.as_ref(), ins, None),
                    }
                }
                if stop || len == 0 {
                    break;
                }
                at = at.wrapping_add(len);
                if visited.contains(&(at, in_flag_branch)) {
                    break;
                }
            }
        }
        probe
    }

    fn walk_ctor_dtor(
        &self,
        entry: u64,
        end_bound: u64,
        vftable_owner: &FxHashMap<u64, (usize, u32)>,
        max_insns: usize,
    ) -> CtorDtorWalk {
        let mut result = CtorDtorWalk::default();
        let mut queue: VecDeque<(u64, SymState, usize)> = VecDeque::new();
        queue.push_back((entry, self.initial_state(), 0));
        let mut visited: FxHashSet<u64> = FxHashSet::default();
        let mut decoded = 0usize;

        while let Some((mut at, mut st, mut step)) = queue.pop_front() {
            if !visited.insert(at) {
                continue;
            }
            while decoded < max_insns && at >= entry && at < end_bound {
                decoded += 1;
                step += 1;
                let Some((ops, len)) = self.lift(at) else { break };
                let mut stop = false;
                for (opc, out, ins) in &ops {
                    match opc {
                        OpCode::CPUI_CBRANCH => {
                            if let Some(t) = ins.first().filter(|v| !is_constant(v)) {
                                if t.offset >= entry && t.offset < end_bound {
                                    queue.push_back((t.offset, st.clone(), step));
                                }
                            }
                        }
                        OpCode::CPUI_BRANCH => {
                            if let Some(t) = ins.first().filter(|v| !is_constant(v)) {
                                if t.offset >= entry && t.offset < end_bound {
                                    queue.push_back((t.offset, st.clone(), step));
                                } else {
                                    result.calls.push(CallEvent {
                                        target: t.offset,
                                        step,
                                    });
                                }
                            }
                            stop = true;
                        }
                        OpCode::CPUI_CALL => {
                            if let Some(t) = ins.first().filter(|v| !is_constant(v)) {
                                result.calls.push(CallEvent { target: t.offset, step });
                            }
                            self.after_call(&mut st);
                        }
                        OpCode::CPUI_CALLIND => {
                            self.after_call(&mut st);
                        }
                        OpCode::CPUI_RETURN => {
                            if st.get_reg(self.ret_reg) == Some(SymVal::This(0)) {
                                result.returns_this = true;
                            }
                            stop = true;
                        }
                        OpCode::CPUI_STORE => {
                            if let (Some(addr_vn), Some(val_vn)) = (ins.get(1), ins.get(2)) {
                                let addr_val = self.eval(&st, addr_vn);
                                let stored_val = self.eval(&st, val_vn);
                                if let Some(SymVal::Const(v)) = stored_val {
                                    if vftable_owner.contains_key(&v) {
                                        match addr_val {
                                            Some(SymVal::This(o)) => {
                                                result.vptr_stores.push(VptrStoreEvent {
                                                    vptr: v,
                                                    offset: Some(o),
                                                    step,
                                                });
                                            }
                                            Some(SymVal::VbaseAddr(..)) => {
                                                result.vptr_stores.push(VptrStoreEvent {
                                                    vptr: v,
                                                    offset: None,
                                                    step,
                                                });
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            self.step(&mut st, *opc, out.as_ref(), ins, None);
                        }
                        _ => self.step(&mut st, *opc, out.as_ref(), ins, None),
                    }
                }
                if stop || len == 0 {
                    break;
                }
                at = at.wrapping_add(len);
                if visited.contains(&at) {
                    break;
                }
            }
        }
        result
    }

    fn harvest_member_accesses(
        &self,
        entry: u64,
        end_bound: u64,
        this_base_off: i64,
        max_insns: usize,
        obs: &mut BTreeMap<(u32, u32), FieldVote>,
    ) {
        let mut queue: VecDeque<(u64, SymState)> = VecDeque::new();
        queue.push_back((entry, self.initial_state()));
        let mut visited: FxHashSet<u64> = FxHashSet::default();
        let mut decoded = 0usize;

        // Track which register/unique holds a recently loaded member `(class_off, width)` to tag float/signed/ptr uses.
        while let Some((mut at, mut st)) = queue.pop_front() {
            if !visited.insert(at) {
                continue;
            }
            let mut loaded_origin: FxHashMap<Key, (u32, u32)> = FxHashMap::default();
            while decoded < max_insns && at >= entry && at < end_bound {
                decoded += 1;
                let Some((ops, len)) = self.lift(at) else { break };
                let mut stop = false;
                for (opc, out, ins) in &ops {
                    match opc {
                        OpCode::CPUI_CBRANCH => {
                            if let Some(t) = ins.first().filter(|v| !is_constant(v)) {
                                if t.offset >= entry && t.offset < end_bound {
                                    queue.push_back((t.offset, st.clone()));
                                }
                            }
                        }
                        OpCode::CPUI_BRANCH => {
                            if let Some(t) = ins.first().filter(|v| !is_constant(v)) {
                                if t.offset >= entry && t.offset < end_bound {
                                    queue.push_back((t.offset, st.clone()));
                                }
                            }
                            stop = true;
                        }
                        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                            self.after_call(&mut st);
                            loaded_origin.clear();
                        }
                        OpCode::CPUI_RETURN => {
                            stop = true;
                        }
                        OpCode::CPUI_STORE => {
                            if let (Some(addr_vn), Some(val_vn)) = (ins.get(1), ins.get(2)) {
                                if let Some(SymVal::This(off)) = self.eval(&st, addr_vn) {
                                    let class_off = this_base_off.wrapping_add(off);
                                    if class_off >= 0
                                        && class_off < i64::from(MAX_MEMBER_OFFSET)
                                        && matches!(val_vn.size, 1 | 2 | 4 | 8 | 16)
                                    {
                                        let v = obs.entry((class_off as u32, val_vn.size)).or_default();
                                        v.count += 1;
                                        if is_float_reg(self.arch, val_vn) && matches!(val_vn.size, 4 | 8) {
                                            v.float_votes += 1;
                                        }
                                    }
                                }
                                // If the address being dereferenced came from loading a member, tag that member as pointer!
                                if let Some(k) = key_of(addr_vn) {
                                    if let Some(&(co, cw)) = loaded_origin.get(&k) {
                                        if cw == self.ptr_size {
                                            obs.entry((co, cw)).or_default().ptr_votes += 1;
                                        }
                                    }
                                }
                            }
                            self.step(&mut st, *opc, out.as_ref(), ins, None);
                        }
                        OpCode::CPUI_LOAD => {
                            if let Some(addr_vn) = ins.get(1) {
                                if let Some(k) = key_of(addr_vn) {
                                    if let Some(&(co, cw)) = loaded_origin.get(&k) {
                                        if cw == self.ptr_size {
                                            obs.entry((co, cw)).or_default().ptr_votes += 1;
                                        }
                                    }
                                }
                            }
                            let mut recorded: Option<(u32, u32, Option<Key>)> = None;
                            let mut on_load = |off: i64, sz: u32, out_vn: Option<&VarnodeData>| {
                                let class_off = this_base_off.wrapping_add(off);
                                if class_off >= 0
                                    && class_off < i64::from(MAX_MEMBER_OFFSET)
                                    && matches!(sz, 1 | 2 | 4 | 8 | 16)
                                {
                                    let v = obs.entry((class_off as u32, sz)).or_default();
                                    v.count += 1;
                                    if out_vn.is_some_and(|vn| is_float_reg(self.arch, vn))
                                        && matches!(sz, 4 | 8)
                                    {
                                        v.float_votes += 1;
                                    }
                                    recorded = Some((class_off as u32, sz, out_vn.and_then(key_of)));
                                }
                            };
                            self.step(&mut st, *opc, out.as_ref(), ins, Some(&mut on_load));
                            if let Some((co, sz, Some(ok))) = recorded {
                                loaded_origin.insert(ok, (co, sz));
                            } else if let Some(ok) = out.as_ref().and_then(key_of) {
                                loaded_origin.remove(&ok);
                            }
                        }
                        _ => {
                            let is_float_op = matches!(
                                opc,
                                OpCode::CPUI_FLOAT_ADD
                                    | OpCode::CPUI_FLOAT_SUB
                                    | OpCode::CPUI_FLOAT_MULT
                                    | OpCode::CPUI_FLOAT_DIV
                                    | OpCode::CPUI_FLOAT_EQUAL
                                    | OpCode::CPUI_FLOAT_NOTEQUAL
                                    | OpCode::CPUI_FLOAT_LESS
                                    | OpCode::CPUI_FLOAT_LESSEQUAL
                                    | OpCode::CPUI_FLOAT_FLOAT2FLOAT
                                    | OpCode::CPUI_FLOAT_TRUNC
                                    | OpCode::CPUI_FLOAT_SQRT
                            );
                            let is_signed_op = matches!(
                                opc,
                                OpCode::CPUI_INT_SLESS
                                    | OpCode::CPUI_INT_SLESSEQUAL
                                    | OpCode::CPUI_INT_SDIV
                                    | OpCode::CPUI_INT_SREM
                                    | OpCode::CPUI_INT_SRIGHT
                                    | OpCode::CPUI_INT_SEXT
                                    | OpCode::CPUI_FLOAT_INT2FLOAT
                            );
                            if is_float_op || is_signed_op {
                                for inp in ins {
                                    if let Some(k) = key_of(inp) {
                                        if let Some(&(co, cw)) = loaded_origin.get(&k) {
                                            let v = obs.entry((co, cw)).or_default();
                                            if is_float_op {
                                                v.float_votes += 1;
                                            }
                                            if is_signed_op {
                                                v.signed_votes += 1;
                                            }
                                        }
                                    }
                                }
                            }
                            // Propagate loaded_origin across simple copies / moves.
                            let propagated = if matches!(opc, OpCode::CPUI_COPY | OpCode::CPUI_SUBPIECE) {
                                ins.first()
                                    .and_then(key_of)
                                    .and_then(|k| loaded_origin.get(&k).copied())
                            } else {
                                None
                            };
                            self.step(&mut st, *opc, out.as_ref(), ins, None);
                            if let Some(ok) = out.as_ref().and_then(key_of) {
                                if let Some(orig) = propagated {
                                    loaded_origin.insert(ok, orig);
                                } else {
                                    loaded_origin.remove(&ok);
                                }
                            }
                        }
                    }
                }
                if stop || len == 0 {
                    break;
                }
                at = at.wrapping_add(len);
                if visited.contains(&at) {
                    break;
                }
            }
        }
    }
}

fn is_float_reg(arch: &Architecture, vn: &VarnodeData) -> bool {
    let Some(space) = vn.space.as_ref() else {
        return false;
    };
    if space.get_type() != kuna_base::space::spacetype::IPTR_PROCESSOR {
        return false;
    }
    let name = arch.translate().get_register_name(space, vn.offset, vn.size as i32);
    name.starts_with("XMM") || name.starts_with("YMM")
}

struct Lifted {
    ops: Ops,
}

impl PcodeEmit for Lifted {
    fn dump(
        &mut self,
        _addr: &Address,
        opc: OpCode,
        outvar: Option<&VarnodeData>,
        vars: &[VarnodeData],
    ) {
        self.ops.push((opc, outvar.cloned(), vars.to_vec()));
    }
}

fn is_constant(vn: &VarnodeData) -> bool {
    vn.space
        .as_ref()
        .is_some_and(|s| s.get_type() == kuna_base::space::spacetype::IPTR_CONSTANT)
}

fn key_of(vn: &VarnodeData) -> Option<Key> {
    let sp = vn.space.as_ref()?;
    let ty = sp.get_type();
    if ty == kuna_base::space::spacetype::IPTR_PROCESSOR
        || ty == kuna_base::space::spacetype::IPTR_INTERNAL
    {
        Some((sp.get_index() as u32, vn.offset, vn.size))
    } else {
        None
    }
}

fn sign_extend(v: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        v as i64
    } else {
        let shift = 64 - bits;
        ((v << shift) as i64) >> shift
    }
}

fn truncate(v: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 {
        v
    } else {
        v & ((1u64 << bits) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtti::kuna_msvchierarchy::{BaseEntry, MsvcClassInfo, MsvcVfTable};
    use crate::rtti::models::{CompleteObjectLocator, Pmd};

    fn dummy_col(offset: u32, cd_offset: u32) -> CompleteObjectLocator {
        CompleteObjectLocator {
            addr: 0x1000,
            signature: 1,
            offset,
            cd_offset,
            p_type_descriptor: 0x2000,
            p_class_hierarchy: 0x3000,
            p_self: Some(0x1000),
        }
    }

    #[test]
    fn layout_reconciliation_prefers_scalar_fields_over_coalesced_zero_store() {
        let mut hier = MsvcHierarchy::default();
        hier.classes.push(MsvcClassInfo {
            td_addr: 0x2000,
            mangled_name: ".?AVWidget@@".into(),
            name: "Widget".into(),
            chd_addr: None,
            chd_attributes: 0,
            all_bases: Vec::new(),
            direct_bases: Vec::new(),
            ancestors: FxHashSet::default(),
            vftables: vec![MsvcVfTable {
                col: dummy_col(0, 0),
                meta_slot: 0x4000,
                base: 0x4008,
                slots: vec![0x1000],
                owner_base_idx: None,
                is_virtual_base: false,
                label: "Widget::vftable".into(),
                col_label: "Widget::RTTI_Complete_Object_Locator".into(),
                struct_name: "Widget_vftable".into(),
            }],
        });

        let vftables = vec![RecoveredVfTableSpec {
            base_addr: 0x4008,
            label: "Widget::vftable".into(),
            struct_name: "Widget_vftable".into(),
            col_offset: 0,
            owner_class_idx: Some(0),
            slots: vec![RecoveredVfSlot {
                target_addr: 0x1000,
                field_name: "vfunc_0".into(),
                is_deleting_dtor: false,
            }],
        }];

        let mut obs = BTreeMap::new();
        // Coalesced 8-byte zero store at +0x08 colliding with two 4-byte scalar fields (+0x08 float, +0x0c int).
        obs.insert((0x08, 8), FieldVote { count: 1, ..Default::default() });
        obs.insert((0x08, 4), FieldVote { count: 3, float_votes: 2, ..Default::default() });
        obs.insert((0x0c, 4), FieldVote { count: 2, signed_votes: 1, ..Default::default() });

        let (fields, size, align) =
            synthesize_class_layout(0, &hier, &[0], &[], &vftables, &obs, Some(0x10), 8);
        assert_eq!(size, 0x10);
        assert_eq!(align, 8);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "vftable");
        assert_eq!(fields[1].offset, 0x08);
        assert!(matches!(
            fields[1].kind,
            RecoveredFieldKind::Primitive { width: 4, hint: FieldTypeHint::Float }
        ));
        assert_eq!(fields[2].offset, 0x0c);
        assert!(matches!(
            fields[2].kind,
            RecoveredFieldKind::Primitive { width: 4, hint: FieldTypeHint::Int }
        ));
    }

    #[test]
    fn diamond_layout_never_inlines_vtordisp_from_non_virtual_base_slice() {
        let mut hier = MsvcHierarchy::default();
        // 0: Tracked (size 0x10), 1: Left (virtual Tracked @0x18), 2: Right (virtual Tracked @0x18),
        // 3: Diamond (Left@0, Right@0x10, virtual Tracked@0x30)
        for (i, n) in ["Tracked", "Left", "Right", "Diamond"].iter().enumerate() {
            hier.classes.push(MsvcClassInfo {
                td_addr: 0x2000 + (i as u64) * 0x40,
                mangled_name: format!(".?AV{n}@@"),
                name: (*n).into(),
                chd_addr: None,
                chd_attributes: 0,
                all_bases: Vec::new(),
                direct_bases: Vec::new(),
                ancestors: FxHashSet::default(),
                vftables: Vec::new(),
            });
        }
        hier.classes[3].direct_bases = vec![
            BaseEntry {
                class_idx: 1,
                num_contained_bases: 1,
                pmd: Pmd { mdisp: 0, pdisp: -1, vdisp: 0 },
                attributes: 0,
            },
            BaseEntry {
                class_idx: 2,
                num_contained_bases: 1,
                pmd: Pmd { mdisp: 0x10, pdisp: -1, vdisp: 0 },
                attributes: 0,
            },
        ];
        hier.classes[3].vftables.push(MsvcVfTable {
            col: dummy_col(0x30, 4),
            meta_slot: 0x5000,
            base: 0x5008,
            slots: vec![0x1000],
            owner_base_idx: Some(0),
            is_virtual_base: true,
            label: "Diamond::vftable_for_Tracked".into(),
            col_label: "Diamond::RTTI_Complete_Object_Locator".into(),
            struct_name: "Diamond_vftable_for_Tracked".into(),
        });

        let completed = vec![
            RecoveredMsvcClass {
                name: "Tracked".into(),
                size: 0x10,
                align: 8,
                vftables: Vec::new(),
                fields: vec![RecoveredClassField {
                    offset: 0,
                    name: "vftable".into(),
                    kind: RecoveredFieldKind::VftablePtr {
                        vftable_struct_name: "Tracked_vftable".into(),
                    },
                }],
            },
            RecoveredMsvcClass {
                name: "Left".into(),
                size: 0x28,
                align: 8,
                vftables: Vec::new(),
                fields: vec![
                    RecoveredClassField { offset: 0, name: "__vbptr".into(), kind: RecoveredFieldKind::Vbptr },
                    RecoveredClassField {
                        offset: 8,
                        name: "field_0x8".into(),
                        kind: RecoveredFieldKind::Primitive { width: 4, hint: FieldTypeHint::Uint },
                    },
                    RecoveredClassField { offset: 0x14, name: "vtordisp_Tracked".into(), kind: RecoveredFieldKind::VtorDisp },
                ],
            },
            RecoveredMsvcClass {
                name: "Right".into(),
                size: 0x28,
                align: 8,
                vftables: Vec::new(),
                fields: vec![
                    RecoveredClassField { offset: 0, name: "__vbptr".into(), kind: RecoveredFieldKind::Vbptr },
                    RecoveredClassField {
                        offset: 8,
                        name: "field_0x8".into(),
                        kind: RecoveredFieldKind::Primitive { width: 4, hint: FieldTypeHint::Uint },
                    },
                    RecoveredClassField { offset: 0x14, name: "vtordisp_Tracked".into(), kind: RecoveredFieldKind::VtorDisp },
                ],
            },
        ];

        let mut obs = BTreeMap::new();
        obs.insert((0x20, 4), FieldVote { count: 1, ..Default::default() });
        let (fields, size, _) =
            synthesize_class_layout(3, &hier, &[0, 1, 2, 3], &completed, &[], &obs, Some(0x40), 8);
        assert_eq!(size, 0x40);
        let vtordisps: Vec<u32> = fields
            .iter()
            .filter(|f| matches!(f.kind, RecoveredFieldKind::VtorDisp))
            .map(|f| f.offset)
            .collect();
        assert_eq!(vtordisps, vec![0x2c], "only Diamond's own vtordisp at +0x2c may appear");
    }
}
