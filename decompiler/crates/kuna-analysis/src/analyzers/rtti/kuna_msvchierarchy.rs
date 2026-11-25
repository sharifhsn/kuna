//! MSVC RTTI class hierarchy, multi-vftable graph, and ancestor-winner slot
//! attribution.

use std::collections::BTreeMap;

use kuna_decomp::kuna_fasthash::{FxHashMap, FxHashSet};

use crate::demangle::demangle_rtti_class_name;

use super::models::{
    read_base_class_array, BaseClassDescriptor, ClassHierarchyDescriptor, CompleteObjectLocator,
    ImageBytes, Pmd, TypeDescriptor,
};
use super::refkind::RefKind;
use super::vftable::{walk_vftable, TextRanges};

const COL_TD_FIELD_OFFSET: u64 = 12;
const MIN_TYPE_INFO_AGREEMENT: usize = 2;

/// One base-class entry inside a class's RTTI2 `BaseClassArray`.
#[derive(Clone, Debug)]
pub struct BaseEntry {
    pub class_idx: usize,
    pub num_contained_bases: u32,
    pub pmd: Pmd,
    pub attributes: u32,
}

impl BaseEntry {
    pub fn is_virtual(&self) -> bool {
        self.pmd.pdisp >= 0
    }
}

/// One validated vftable belonging to an MSVC polymorphic class.
#[derive(Clone, Debug)]
pub struct MsvcVfTable {
    pub col: CompleteObjectLocator,
    pub meta_slot: u64,
    pub base: u64,
    pub slots: Vec<u64>,
    pub owner_base_idx: Option<usize>,
    pub is_virtual_base: bool,
    pub label: String,
    pub col_label: String,
    pub struct_name: String,
}

impl MsvcVfTable {
    pub fn range(&self, rk: &RefKind) -> (u64, u64) {
        let end = self.base + (self.slots.len() as u64) * (rk.ptr_size() as u64);
        (self.base, end)
    }
}

/// One recovered MSVC polymorphic class (or base class reachable via RTTI).
#[derive(Clone, Debug)]
pub struct MsvcClassInfo {
    pub td_addr: u64,
    pub mangled_name: String,
    pub name: String,
    pub chd_addr: Option<u64>,
    pub chd_attributes: u32,
    pub all_bases: Vec<BaseEntry>,
    pub direct_bases: Vec<BaseEntry>,
    pub ancestors: FxHashSet<usize>,
    pub vftables: Vec<MsvcVfTable>,
}

/// Complete recovered MSVC RTTI hierarchy for one PE image.
#[derive(Clone, Debug, Default)]
pub struct MsvcHierarchy {
    pub classes: Vec<MsvcClassInfo>,
    pub td_to_idx: FxHashMap<u64, usize>,
    pub type_info_vftable: Option<u64>,
}

/// Slot ownership verdict after ancestor-winner and `/OPT:ICF` arbitration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotAttribution {
    Unique {
        class_idx: usize,
        vf_idx: usize,
        slot_idx: usize,
    },
    IcfShared {
        classes: Vec<usize>,
    },
}

impl MsvcHierarchy {
    /// Deterministic base-first topological ordering of class indices.
    pub fn topological_order(&self) -> Vec<usize> {
        let n = self.classes.len();
        let mut indegree = vec![0usize; n];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (c, cls) in self.classes.iter().enumerate() {
            let mut seen = FxHashSet::default();
            for b in &cls.direct_bases {
                if b.class_idx != c && b.class_idx < n && seen.insert(b.class_idx) {
                    dependents[b.class_idx].push(c);
                    indegree[c] += 1;
                }
            }
        }
        let mut ready: std::collections::BTreeSet<usize> = (0..n)
            .filter(|&i| indegree[i] == 0)
            .collect();
        let mut order = Vec::with_capacity(n);
        while let Some(u) = ready.pop_first() {
            order.push(u);
            for &v in &dependents[u] {
                indegree[v] = indegree[v].saturating_sub(1);
                if indegree[v] == 0 {
                    ready.insert(v);
                }
            }
        }
        if order.len() < n {
            let placed: FxHashSet<usize> = order.iter().copied().collect();
            for i in 0..n {
                if !placed.contains(&i) {
                    order.push(i);
                }
            }
        }
        order
    }
}

/// Short unqualified tail of a C++ class name (`ns::Foo` -> `Foo`).
pub fn short_class_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// Scan every section for candidate RTTI0 `TypeDescriptor`s.
pub fn find_type_descriptors(img: &ImageBytes, rk: &RefKind) -> Vec<TypeDescriptor> {
    let mut out = Vec::new();
    for name_addr in img.scan_prefix(b".?A") {
        let Some(td_addr) = name_addr.checked_sub(rk.type_descriptor_name_offset()) else {
            continue;
        };
        if let Some(td) = TypeDescriptor::read(img, rk, td_addr) {
            out.push(td);
        }
    }
    out
}

/// Pick the `type_info` vftable pointer agreed on by the most `TypeDescriptor`s.
pub fn pick_common_type_info_vftable(descriptors: &[TypeDescriptor]) -> Option<u64> {
    let mut counts: FxHashMap<u64, usize> = FxHashMap::default();
    for td in descriptors {
        if td.p_vftable != 0 {
            *counts.entry(td.p_vftable).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .filter(|&(_, n)| n >= MIN_TYPE_INFO_AGREEMENT)
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(vma, _)| vma)
}

/// Recover the full MSVC RTTI class hierarchy and multi-vftable graph from a PE image.
pub fn recover_msvc_hierarchy(
    img: &ImageBytes,
    rk: &RefKind,
    text: &TextRanges,
) -> MsvcHierarchy {
    let descriptors = find_type_descriptors(img, rk);
    let Some(type_info_vftable) = pick_common_type_info_vftable(&descriptors) else {
        return MsvcHierarchy::default();
    };
    let mut tds: Vec<TypeDescriptor> = descriptors
        .into_iter()
        .filter(|td| td.p_vftable == type_info_vftable)
        .collect();
    tds.sort_by_key(|td| td.addr);
    tds.dedup_by_key(|td| td.addr);

    let mut hier = recover_from_descriptors(img, rk, text, &tds);
    hier.type_info_vftable = Some(type_info_vftable);
    hier
}

/// Recover the hierarchy from a pre-filtered slice of `TypeDescriptor`s (shared with tests).
pub fn recover_from_descriptors(
    img: &ImageBytes,
    rk: &RefKind,
    text: &TextRanges,
    tds: &[TypeDescriptor],
) -> MsvcHierarchy {
    let td_addrs: FxHashSet<u64> = tds.iter().map(|td| td.addr).collect();
    let refs = img.scan_refs(rk, &td_addrs);

    let mut seen_cols = FxHashSet::<u64>::default();
    let mut validated: Vec<(CompleteObjectLocator, ClassHierarchyDescriptor, Vec<BaseClassDescriptor>)> =
        Vec::new();

    for td in tds {
        let Some(ref_list) = refs.get(&td.addr) else {
            continue;
        };
        for &ref_vma in ref_list {
            let Some(col_addr) = ref_vma.checked_sub(COL_TD_FIELD_OFFSET) else {
                continue;
            };
            if !seen_cols.insert(col_addr) {
                continue;
            }
            let Some(col) = CompleteObjectLocator::read(img, rk, col_addr) else {
                continue;
            };
            if col.p_type_descriptor != td.addr {
                continue;
            }
            let Some(chd) = ClassHierarchyDescriptor::read(img, rk, col.p_class_hierarchy) else {
                continue;
            };
            let bcd_addrs = read_base_class_array(img, rk, chd.p_base_class_array, chd.num_base_classes);
            if bcd_addrs.is_empty() {
                continue;
            }
            let mut bcds = Vec::with_capacity(bcd_addrs.len());
            for a in bcd_addrs {
                if let Some(bcd) = BaseClassDescriptor::read(img, rk, a) {
                    bcds.push(bcd);
                }
            }
            if bcds.is_empty() {
                continue;
            }
            validated.push((col, chd, bcds));
        }
    }

    if validated.is_empty() {
        return MsvcHierarchy::default();
    }

    let col_addrs: FxHashSet<u64> = validated.iter().map(|(c, _, _)| c.addr).collect();
    let mut meta_slots: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for (slot, col_addr) in img.scan_ptr_slots(rk, &col_addrs) {
        meta_slots.entry(col_addr).or_default().push(slot);
    }

    let mut td_map: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let register_td = |addr: u64, map: &mut BTreeMap<u64, (String, String)>| {
        if map.contains_key(&addr) {
            return;
        }
        if let Some(td) = TypeDescriptor::read(img, rk, addr) {
            if let Some(name) = demangle_rtti_class_name(&td.mangled_name) {
                map.insert(addr, (td.mangled_name, name));
            }
        }
    };

    for (col, _, bcds) in &validated {
        register_td(col.p_type_descriptor, &mut td_map);
        for bcd in bcds {
            register_td(bcd.p_type_descriptor, &mut td_map);
        }
    }

    let mut hier = MsvcHierarchy::default();
    for (td_addr, (mangled_name, name)) in td_map {
        let idx = hier.classes.len();
        hier.td_to_idx.insert(td_addr, idx);
        hier.classes.push(MsvcClassInfo {
            td_addr,
            mangled_name,
            name,
            chd_addr: None,
            chd_attributes: 0,
            all_bases: Vec::new(),
            direct_bases: Vec::new(),
            ancestors: FxHashSet::default(),
            vftables: Vec::new(),
        });
    }

    // Group validated COLs per class and populate base lists.
    let mut cols_by_class: Vec<Vec<(CompleteObjectLocator, ClassHierarchyDescriptor, Vec<BaseClassDescriptor>)>> =
        vec![Vec::new(); hier.classes.len()];
    for item in validated {
        if let Some(&idx) = hier.td_to_idx.get(&item.0.p_type_descriptor) {
            cols_by_class[idx].push(item);
        }
    }

    for (cls_idx, mut items) in cols_by_class.into_iter().enumerate() {
        if items.is_empty() {
            continue;
        }
        items.sort_by_key(|(col, _, _)| (col.offset, col.addr));

        // Populate class hierarchy & direct bases from the first (primary/lowest-offset) COL.
        let (_, ref chd0, ref bcds0) = items[0];
        hier.classes[cls_idx].chd_addr = Some(chd0.addr);
        hier.classes[cls_idx].chd_attributes = chd0.attributes;

        let entries: Vec<BaseEntry> = bcds0
            .iter()
            .filter_map(|bcd| {
                let &bidx = hier.td_to_idx.get(&bcd.p_type_descriptor)?;
                Some(BaseEntry {
                    class_idx: bidx,
                    num_contained_bases: bcd.num_contained_bases,
                    pmd: bcd.pmd,
                    attributes: bcd.attributes,
                })
            })
            .collect();

        let direct = extract_direct_bases(&entries, cls_idx);
        let all_bases: Vec<BaseEntry> = entries
            .into_iter()
            .skip(1)
            .filter(|b| b.class_idx != cls_idx)
            .collect();
        hier.classes[cls_idx].all_bases = all_bases;
        hier.classes[cls_idx].direct_bases = direct;

        // Recover every vftable associated with every COL of this class.
        let mut raw_vfts: Vec<(CompleteObjectLocator, u64, u64, Vec<u64>)> = Vec::new();
        let mut seen_vft_bases = FxHashSet::<u64>::default();
        for (col, _, _) in items {
            let slots_for_col = meta_slots.get(&col.addr).map(Vec::as_slice).unwrap_or_default();
            if let Some((meta_slot, vft_base)) = recover_vftable_meta(img, rk, slots_for_col) {
                if !seen_vft_bases.insert(vft_base) {
                    continue;
                }
                if let Some(vt) = walk_vftable(img, rk, text, vft_base) {
                    raw_vfts.push((col, meta_slot, vft_base, vt.slots));
                }
            }
        }
        raw_vfts.sort_by_key(|(col, _, base, _)| (col.offset, *base));

        // Resolve secondary vftable owning bases and assign unique labels.
        let mut used_owner_names: FxHashMap<String, usize> = FxHashMap::default();
        let class_name = hier.classes[cls_idx].name.clone();
        let direct_snapshot = hier.classes[cls_idx].direct_bases.clone();
        let all_snapshot = hier.classes[cls_idx].all_bases.clone();

        for (vf_ord, (col, meta_slot, vft_base, slots)) in raw_vfts.into_iter().enumerate() {
            let (owner_base_idx, is_virtual_base) = if col.offset == 0 {
                (None, false)
            } else {
                match_secondary_vftable_owner(&col, &direct_snapshot, &all_snapshot)
            };
            let (label, col_label, struct_name) = if col.offset == 0 && vf_ord == 0 {
                (
                    format!("{class_name}::vftable"),
                    format!("{class_name}::RTTI_Complete_Object_Locator"),
                    format!("{class_name}_vftable"),
                )
            } else {
                let suffix = match owner_base_idx {
                    Some(bidx) => {
                        let base_short = short_class_name(&hier.classes[bidx].name).to_string();
                        let count = used_owner_names.entry(base_short.clone()).or_insert(0);
                        *count += 1;
                        if *count == 1 {
                            format!("for_{base_short}")
                        } else {
                            format!("for_{base_short}_0x{:x}", col.offset)
                        }
                    }
                    None => format!("0x{:x}", col.offset),
                };
                let col_lbl = if vf_ord == 0 {
                    format!("{class_name}::RTTI_Complete_Object_Locator")
                } else {
                    format!("{class_name}::RTTI_Complete_Object_Locator_{suffix}")
                };
                (
                    format!("{class_name}::vftable_{suffix}"),
                    col_lbl,
                    format!("{class_name}_vftable_{suffix}"),
                )
            };
            hier.classes[cls_idx].vftables.push(MsvcVfTable {
                col,
                meta_slot,
                base: vft_base,
                slots,
                owner_base_idx,
                is_virtual_base,
                label,
                col_label,
                struct_name,
            });
        }
    }

    // Compute transitive ancestors per class.
    compute_ancestors(&mut hier.classes);
    hier
}

/// Extract direct bases using the MSVC RTTI1 `numContainedBases` preorder subtree rule.
pub fn extract_direct_bases(entries: &[BaseEntry], self_idx: usize) -> Vec<BaseEntry> {
    let mut direct = Vec::new();
    let mut i = 1usize;
    while i < entries.len() {
        let entry = &entries[i];
        if entry.class_idx != self_idx {
            direct.push(entry.clone());
        }
        let skip = 1usize.saturating_add(entry.num_contained_bases as usize);
        i = i.saturating_add(skip);
    }
    direct
}

fn match_secondary_vftable_owner(
    col: &CompleteObjectLocator,
    direct_bases: &[BaseEntry],
    all_bases: &[BaseEntry],
) -> (Option<usize>, bool) {
    let off = col.offset as i32;
    if let Some(b) = direct_bases.iter().find(|b| !b.is_virtual() && b.pmd.mdisp == off) {
        return (Some(b.class_idx), false);
    }
    if let Some(b) = all_bases.iter().find(|b| !b.is_virtual() && b.pmd.mdisp == off) {
        return (Some(b.class_idx), false);
    }
    // Virtual base subobject (pdisp >= 0): prefer direct virtual base, else any virtual base.
    let mut virt_direct: Vec<usize> = direct_bases
        .iter()
        .filter(|b| b.is_virtual())
        .map(|b| b.class_idx)
        .collect();
    virt_direct.dedup();
    if virt_direct.len() == 1 {
        return (Some(virt_direct[0]), true);
    }
    let mut virt_all: Vec<usize> = all_bases
        .iter()
        .filter(|b| b.is_virtual())
        .map(|b| b.class_idx)
        .collect();
    virt_all.sort_unstable();
    virt_all.dedup();
    if let Some(&first) = virt_all.first() {
        return (Some(first), true);
    }
    (None, col.cd_offset != 0)
}

fn compute_ancestors(classes: &mut [MsvcClassInfo]) {
    let direct: Vec<Vec<usize>> = classes
        .iter()
        .map(|c| {
            let mut v: Vec<usize> = c.direct_bases.iter().map(|b| b.class_idx).collect();
            v.extend(c.all_bases.iter().map(|b| b.class_idx));
            v.sort_unstable();
            v.dedup();
            v
        })
        .collect();

    for i in 0..classes.len() {
        let mut anc = FxHashSet::default();
        let mut stack = direct[i].clone();
        while let Some(b) = stack.pop() {
            if b == i || b >= classes.len() {
                continue;
            }
            if anc.insert(b) {
                stack.extend(&direct[b]);
            }
        }
        classes[i].ancestors = anc;
    }
}

fn recover_vftable_meta(img: &ImageBytes, rk: &RefKind, meta_slots: &[u64]) -> Option<(u64, u64)> {
    let ptr = rk.ptr_size() as u64;
    for &slot in meta_slots {
        let vftable = slot + ptr;
        if let Some(first) = img.read(vftable, rk.ptr_size()) {
            let first_ptr = rk.read_ptr(first);
            if first_ptr != 0 && img.contains(first_ptr) {
                return Some((slot, vftable));
            }
        }
    }
    None
}

/// Attribute every vftable slot target to its defining ancestor class, flagging
/// unrelated multi-class collisions (`/OPT:ICF` or `_purecall`) as [`SlotAttribution::IcfShared`].
pub fn attribute_vtable_slots(hier: &MsvcHierarchy) -> BTreeMap<u64, SlotAttribution> {
    let mut claims: BTreeMap<u64, Vec<(usize, usize, usize)>> = BTreeMap::new();
    for (c, cls) in hier.classes.iter().enumerate() {
        for (vf_idx, vf) in cls.vftables.iter().enumerate() {
            for (slot_idx, &fn_addr) in vf.slots.iter().enumerate() {
                claims.entry(fn_addr).or_default().push((c, vf_idx, slot_idx));
            }
        }
    }

    let mut out = BTreeMap::new();
    for (fn_addr, list) in claims {
        let mut unique_classes: Vec<usize> = list.iter().map(|&(c, _, _)| c).collect();
        unique_classes.sort_unstable();
        unique_classes.dedup();

        // Keep only classes that have no strict ancestor also claiming `fn_addr`.
        let winners: Vec<usize> = unique_classes
            .iter()
            .copied()
            .filter(|&c| {
                !unique_classes
                    .iter()
                    .any(|&other| other != c && hier.classes[c].ancestors.contains(&other))
            })
            .collect();

        if winners.len() == 1 {
            let winner = winners[0];
            // Prefer primary (offset == 0) vftable if the winning class lists it in multiple tables.
            let best = list
                .iter()
                .copied()
                .filter(|&(c, _, _)| c == winner)
                .min_by_key(|&(c, vf, slot)| (hier.classes[c].vftables[vf].col.offset, vf, slot))
                .expect("winner present");
            out.insert(
                fn_addr,
                SlotAttribution::Unique {
                    class_idx: best.0,
                    vf_idx: best.1,
                    slot_idx: best.2,
                },
            );
        } else if winners.len() > 1 {
            out.insert(fn_addr, SlotAttribution::IcfShared { classes: winners });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(idx: usize, contained: u32, mdisp: i32, pdisp: i32) -> BaseEntry {
        BaseEntry {
            class_idx: idx,
            num_contained_bases: contained,
            pmd: Pmd { mdisp, pdisp, vdisp: if pdisp >= 0 { 4 } else { 0 } },
            attributes: 0,
        }
    }

    #[test]
    fn preorder_direct_bases_handles_single_mi_and_diamond() {
        // Single chain: C(2) -> B(1) -> A(0)
        let chain = vec![be(2, 2, 0, -1), be(1, 1, 0, -1), be(0, 0, 0, -1)];
        let direct = extract_direct_bases(&chain, 2);
        assert_eq!(direct.iter().map(|b| b.class_idx).collect::<Vec<_>>(), vec![1]);

        // Multiple inheritance: Actor(2) -> Entity(0), Serializable(0)
        let mi = vec![be(2, 2, 0, -1), be(0, 0, 0, -1), be(1, 0, 0x28, -1)];
        let direct = extract_direct_bases(&mi, 2);
        assert_eq!(direct.iter().map(|b| b.class_idx).collect::<Vec<_>>(), vec![0, 1]);

        // Diamond: Diamond(4) -> Left(1) -> Tracked(0), Right(1) -> Tracked(0)
        let diamond = vec![
            be(3, 4, 0, -1),
            be(1, 1, 0, -1),
            be(0, 0, 0, 0),
            be(2, 1, 0x10, -1),
            be(0, 0, 0, 0),
        ];
        let direct = extract_direct_bases(&diamond, 3);
        assert_eq!(direct.iter().map(|b| b.class_idx).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn multi_vftable_p_self_validation_ancestor_winner_and_icf_guard() {
        use super::super::refkind::End;

        let ib = 0x1_4000_0000u64;
        let rk = RefKind::new(true, ib, End::Little);
        let text_base = ib + 0x1000;
        let rdata_base = ib + 0x2000;
        let data_base = ib + 0x3000;
        let type_info_vt = rdata_base;

        let put_u32 = |v: &mut [u8], off: usize, x: u32| {
            v[off..off + 4].copy_from_slice(&x.to_le_bytes());
        };
        let put_i32 = |v: &mut [u8], off: usize, x: i32| {
            v[off..off + 4].copy_from_slice(&x.to_le_bytes());
        };
        let put_u64 = |v: &mut [u8], off: usize, x: u64| {
            v[off..off + 8].copy_from_slice(&x.to_le_bytes());
        };

        let mut rdata = vec![0u8; 0x600];
        let mut data = vec![0u8; 0x200];
        let code = vec![0xC3u8; 0x100];

        // 4 TypeDescriptors: BaseA (@0x00), BaseB (@0x40), Derived (@0x80), Unrelated (@0xc0).
        let td_a = data_base;
        let td_b = data_base + 0x40;
        let td_d = data_base + 0x80;
        let td_u = data_base + 0xc0;
        for (off, name) in [
            (0x00usize, b".?AVBaseA@@\0".as_slice()),
            (0x40, b".?AVBaseB@@\0".as_slice()),
            (0x80, b".?AVDerived@@\0".as_slice()),
            (0xc0, b".?AVUnrelated@@\0".as_slice()),
        ] {
            put_u64(&mut data, off, type_info_vt);
            data[off + 16..off + 16 + name.len()].copy_from_slice(name);
        }

        // Helper to write a 1-base RTTI1 (24 bytes) at `rdata + off`.
        let write_bcd = |v: &mut [u8], off: usize, td: u64, contained: u32, mdisp: i32| {
            put_u32(v, off, (td - ib) as u32);
            put_u32(v, off + 4, contained);
            put_i32(v, off + 8, mdisp);
            put_i32(v, off + 12, -1);
            put_i32(v, off + 16, 0);
            put_u32(v, off + 20, 0);
        };

        // BaseA RTTI: COL @0x020, CHD @0x040, BCA @0x050, BCD @0x060, vft @0x088 (meta @0x080)
        put_u32(&mut rdata, 0x020, 1);
        put_u32(&mut rdata, 0x02c, (td_a - ib) as u32);
        put_u32(&mut rdata, 0x030, (rdata_base + 0x040 - ib) as u32);
        put_u32(&mut rdata, 0x034, (rdata_base + 0x020 - ib) as u32); // pSelf valid
        put_u32(&mut rdata, 0x048, 1);
        put_u32(&mut rdata, 0x04c, (rdata_base + 0x050 - ib) as u32);
        put_u32(&mut rdata, 0x050, (rdata_base + 0x060 - ib) as u32);
        write_bcd(&mut rdata, 0x060, td_a, 0, 0);
        put_u64(&mut rdata, 0x080, rdata_base + 0x020);
        put_u64(&mut rdata, 0x088, text_base + 0x10); // inherited BaseA::vfunc_0
        put_u64(&mut rdata, 0x090, text_base + 0x20); // ICF-shared with Unrelated

        // BaseB RTTI: COL @0x100, CHD @0x120, BCA @0x130, BCD @0x140, vft @0x168 (meta @0x160)
        put_u32(&mut rdata, 0x100, 1);
        put_u32(&mut rdata, 0x10c, (td_b - ib) as u32);
        put_u32(&mut rdata, 0x110, (rdata_base + 0x120 - ib) as u32);
        put_u32(&mut rdata, 0x114, (rdata_base + 0x100 - ib) as u32);
        put_u32(&mut rdata, 0x128, 1);
        put_u32(&mut rdata, 0x12c, (rdata_base + 0x130 - ib) as u32);
        put_u32(&mut rdata, 0x130, (rdata_base + 0x140 - ib) as u32);
        write_bcd(&mut rdata, 0x140, td_b, 0, 0);
        put_u64(&mut rdata, 0x160, rdata_base + 0x100);
        put_u64(&mut rdata, 0x168, text_base + 0x30);

        // Derived (BaseA@0, BaseB@0x20):
        //   COL0 (offset=0) @0x200, COL1 (offset=0x20) @0x220, CHD @0x240, BCA @0x250, BCDs @0x260..0x2a8
        put_u32(&mut rdata, 0x200, 1);
        put_u32(&mut rdata, 0x204, 0);
        put_u32(&mut rdata, 0x20c, (td_d - ib) as u32);
        put_u32(&mut rdata, 0x210, (rdata_base + 0x240 - ib) as u32);
        put_u32(&mut rdata, 0x214, (rdata_base + 0x200 - ib) as u32);

        put_u32(&mut rdata, 0x220, 1);
        put_u32(&mut rdata, 0x224, 0x20);
        put_u32(&mut rdata, 0x22c, (td_d - ib) as u32);
        put_u32(&mut rdata, 0x230, (rdata_base + 0x240 - ib) as u32);
        put_u32(&mut rdata, 0x234, (rdata_base + 0x220 - ib) as u32);

        put_u32(&mut rdata, 0x244, 1); // CHD_MULTINH
        put_u32(&mut rdata, 0x248, 3);
        put_u32(&mut rdata, 0x24c, (rdata_base + 0x250 - ib) as u32);
        put_u32(&mut rdata, 0x250, (rdata_base + 0x260 - ib) as u32);
        put_u32(&mut rdata, 0x254, (rdata_base + 0x278 - ib) as u32);
        put_u32(&mut rdata, 0x258, (rdata_base + 0x290 - ib) as u32);
        write_bcd(&mut rdata, 0x260, td_d, 2, 0);
        write_bcd(&mut rdata, 0x278, td_a, 0, 0);
        write_bcd(&mut rdata, 0x290, td_b, 0, 0x20);

        // Derived primary vftable @0x2c8 (inherits BaseA::vfunc_0 @text+0x10, overrides slot 1 @text+0x40)
        put_u64(&mut rdata, 0x2c0, rdata_base + 0x200);
        put_u64(&mut rdata, 0x2c8, text_base + 0x10);
        put_u64(&mut rdata, 0x2d0, text_base + 0x40);
        // Derived secondary vftable @0x2e8 (offset 0x20 -> BaseB)
        put_u64(&mut rdata, 0x2e0, rdata_base + 0x220);
        put_u64(&mut rdata, 0x2e8, text_base + 0x50);

        // Unrelated class sharing text+0x20 with BaseA (ICF collision)
        put_u32(&mut rdata, 0x300, 1);
        put_u32(&mut rdata, 0x30c, (td_u - ib) as u32);
        put_u32(&mut rdata, 0x310, (rdata_base + 0x320 - ib) as u32);
        put_u32(&mut rdata, 0x314, (rdata_base + 0x300 - ib) as u32);
        put_u32(&mut rdata, 0x328, 1);
        put_u32(&mut rdata, 0x32c, (rdata_base + 0x330 - ib) as u32);
        put_u32(&mut rdata, 0x330, (rdata_base + 0x340 - ib) as u32);
        write_bcd(&mut rdata, 0x340, td_u, 0, 0);
        put_u64(&mut rdata, 0x360, rdata_base + 0x300);
        put_u64(&mut rdata, 0x368, text_base + 0x20); // ICF shared!

        // Bogus COL with bad pSelf @0x400 pointing at td_u -> must be rejected.
        put_u32(&mut rdata, 0x400, 1);
        put_u32(&mut rdata, 0x40c, (td_u - ib) as u32);
        put_u32(&mut rdata, 0x410, (rdata_base + 0x320 - ib) as u32);
        put_u32(&mut rdata, 0x414, 0xdead); // bad pSelf!

        let img = ImageBytes::from_spans(vec![
            (text_base, &code),
            (rdata_base, &rdata),
            (data_base, &data),
        ]);
        let text = TextRanges::for_test(vec![(text_base, text_base + code.len() as u64)]);
        let hier = recover_msvc_hierarchy(&img, &rk, &text);
        assert_eq!(hier.classes.len(), 4);

        let idx_of = |n: &str| hier.classes.iter().position(|c| c.name == n).unwrap();
        let ia = idx_of("BaseA");
        let ib_idx = idx_of("BaseB");
        let id = idx_of("Derived");
        let iu = idx_of("Unrelated");

        // Bogus COL rejected: Unrelated has only 1 vftable.
        assert_eq!(hier.classes[iu].vftables.len(), 1);

        // Derived has both primary + secondary BaseB vftables and exact direct bases.
        assert_eq!(hier.classes[id].vftables.len(), 2);
        assert_eq!(hier.classes[id].vftables[0].label, "Derived::vftable");
        assert_eq!(hier.classes[id].vftables[1].label, "Derived::vftable_for_BaseB");
        assert_eq!(hier.classes[id].vftables[1].owner_base_idx, Some(ib_idx));
        assert!(hier.classes[id].ancestors.contains(&ia));
        assert!(hier.classes[id].ancestors.contains(&ib_idx));

        // Topological order puts BaseA and BaseB before Derived.
        let topo = hier.topological_order();
        let pos = |x: usize| topo.iter().position(|&c| c == x).unwrap();
        assert!(pos(ia) < pos(id));
        assert!(pos(ib_idx) < pos(id));

        // Ancestor-winner attribution: text+0x10 goes to BaseA, NOT Derived;
        // text+0x20 is ICF-shared between BaseA and Unrelated!
        let attr = attribute_vtable_slots(&hier);
        assert_eq!(
            attr.get(&(text_base + 0x10)),
            Some(&SlotAttribution::Unique { class_idx: ia, vf_idx: 0, slot_idx: 0 })
        );
        assert_eq!(
            attr.get(&(text_base + 0x40)),
            Some(&SlotAttribution::Unique { class_idx: id, vf_idx: 0, slot_idx: 1 })
        );
        assert!(matches!(attr.get(&(text_base + 0x20)), Some(SlotAttribution::IcfShared { .. })));
    }
}
