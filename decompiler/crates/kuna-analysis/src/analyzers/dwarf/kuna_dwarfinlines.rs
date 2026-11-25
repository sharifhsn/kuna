//! Addresses and names explicitly attributed to inline calls by a DWARF producer.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{AttributeValue, Dwarf, Unit, UnitOffset};
use kuna_decomp::kuna_inlinesites::InlineeId;

use super::{kuna_cppproto, DieSnap, Reader};
use crate::pass::InlineSiteFact;

fn referenced_die(unit: &Unit<Reader<'_>>, offset: usize, snap: &DieSnap) -> Option<usize> {
    if let Some(target) = snap.origin_ref {
        return Some(target);
    }
    let die = unit.entry(UnitOffset(offset)).ok()?;
    [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification]
        .into_iter()
        .find_map(|attr| match die.attr_value(attr)? {
            AttributeValue::DebugInfoRef(target) => {
                target.to_unit_offset(&unit.header).map(|o| o.0)
            }
            _ => None,
        })
}

fn recorded_ranges(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    offset: usize,
) -> Option<Vec<(u64, u64)>> {
    let entry = unit.entry(UnitOffset(offset)).ok()?;
    let mut records = dwarf.die_ranges(unit, &entry).ok()?;
    let mut ranges = Vec::new();
    while let Some(r) = records.next().ok()? {
        if r.begin > r.end {
            return None;
        }
        if r.begin < r.end {
            ranges.push((r.begin, r.end));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    (!merged.is_empty()).then_some(merged)
}

pub(super) fn site(
    dwarf: &Dwarf<Reader<'_>>,
    unit: &Unit<Reader<'_>>,
    dies: &BTreeMap<usize, DieSnap>,
    offset: usize,
    inline: &DieSnap,
    caller_ranges: &mut BTreeMap<usize, Vec<(u64, u64)>>,
) -> Option<InlineSiteFact> {
    let mut parent = inline.parent?;
    let mut depth = 0u16;
    let (owner, caller) = loop {
        let ancestor = dies.get(&parent)?;
        if ancestor.tag == gimli::DW_TAG_subprogram {
            let die = unit.entry(UnitOffset(parent)).ok()?;
            let entry_pc = die
                .attr_value(gimli::DW_AT_entry_pc)
                .and_then(|v| dwarf.attr_address(unit, v).ok().flatten());
            break (parent, entry_pc.or(ancestor.low_pc)?);
        }
        if ancestor.tag == gimli::DW_TAG_inlined_subroutine {
            depth = depth.checked_add(1)?;
        }
        parent = ancestor.parent?;
    };

    let record = unit.entry(UnitOffset(offset)).ok()?;
    let has_origin = record.attr_value(gimli::DW_AT_abstract_origin).is_some()
        || record.attr_value(gimli::DW_AT_specification).is_some();
    let mut origin = if has_origin {
        referenced_die(unit, offset, inline)?
    } else {
        offset
    };
    let mut seen = BTreeSet::new();
    let name = loop {
        if !seen.insert(origin) {
            return None;
        }
        let target = dies.get(&origin)?;
        if origin != offset && target.tag != gimli::DW_TAG_subprogram {
            return None;
        }
        if !target.name.is_empty() {
            break kuna_cppproto::qualified_name(target, dies);
        }
        origin = referenced_die(unit, origin, target)?;
    };
    let id = UnitOffset(origin).to_debug_info_offset(&unit.header)?.0 as u64;
    let ranges = recorded_ranges(dwarf, unit, offset)?;
    let enclosing = caller_ranges
        .entry(owner)
        .or_insert_with(|| recorded_ranges(dwarf, unit, owner).unwrap_or_default());
    if !enclosing
        .iter()
        .any(|&(start, end)| start <= caller && caller < end)
    {
        return None;
    }
    if !ranges.iter().all(|&(start, end)| {
        let index = enclosing.partition_point(|&(_, stop)| stop <= start);
        enclosing
            .get(index)
            .is_some_and(|&(a, b)| a <= start && end <= b)
    }) {
        return None;
    }
    Some(InlineSiteFact {
        caller_addr: caller,
        inlinee_id: InlineeId::Dwarf(id),
        inlinee_name: name,
        depth,
        ranges,
    })
}
