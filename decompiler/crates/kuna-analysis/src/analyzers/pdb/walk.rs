//! Walk the global and per-module symbol streams of an opened `.pdb` to recover
//! functions, prototypes, no-return flags, typed globals, stack locals, and
//! `S_INLINESITE` call-site ranges.

use std::collections::{BTreeMap, HashMap};

use pdb::{FallibleIterator, IdData, IdFinder, IdIndex, Inlinee, PdbInternalSectionOffset, SymbolData, TypeIndex};

use crate::pass::InlineSiteFact;

use super::types::PdbTypeBuilder;

/// One recovered function name at its absolute VMA (used by `kuna_pdbinterior`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbFunc {
    pub vma: u64,
    pub name: String,
}

/// One module-stream procedure record, global or local, at absolute VMAs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PdbProcedure {
    pub start: u64,
    pub end: Option<u64>,
}

/// One recovered function from either a module procedure record or a global public.
#[derive(Clone, Debug)]
pub struct PdbFuncFact {
    pub vma: u64,
    pub name: String,
    pub type_index: Option<TypeIndex>,
    pub param_names: Vec<String>,
    pub noreturn: bool,
    pub from_proc: bool,
}

/// One recovered typed global variable (`S_GDATA32`/`S_LDATA32`).
#[derive(Clone, Debug)]
pub struct PdbGlobalFact {
    pub vma: u64,
    pub name: String,
    pub type_index: TypeIndex,
    pub global: bool,
}

/// One recovered stack local variable (`S_BPREL32`, `S_REGREL32`, or `S_LOCAL` + `S_DEFRANGE_*`).
#[derive(Clone, Debug)]
pub struct PdbLocalFact {
    pub func_addr: u64,
    pub name: String,
    pub type_index: TypeIndex,
    pub stack_offset: i64,
}

/// Complete output of walking a PDB's global and module symbol streams.
#[derive(Default, Debug)]
pub struct PdbWalkResult {
    pub functions: Vec<PdbFuncFact>,
    pub globals: Vec<PdbGlobalFact>,
    pub locals: Vec<PdbLocalFact>,
    pub inline_sites: Vec<InlineSiteFact>,
}

/// The `S_LPROC32`/`S_GPROC32` record kinds (plain, `_ST`, `_ID` and DPC forms).
const PROCEDURE_KINDS: [u16; 8] = [0x100a, 0x100b, 0x110f, 0x1110, 0x1146, 0x1147, 0x1155, 0x1156];

const S_BPREL32_ST: u16 = 0x1006;
const S_FRAMEPROC: u16 = 0x1012;
const S_BPREL32: u16 = 0x110b;
const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16 = 0x1144;
const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
const S_LPROC32_ID: u16 = 0x1146;
const S_GPROC32_ID: u16 = 0x1147;
const S_LPROC32_DPC_ID: u16 = 0x1156;

const CV_REG_ESP: u16 = 21;
const CV_REG_EBP: u16 = 22;
const CV_AMD64_RBP: u16 = 334;
const CV_AMD64_RSP: u16 = 335;
const CV_ALLREG_VFRAME: u16 = 30006;

#[derive(Clone, Copy, Debug)]
struct FrameProcInfo {
    cb_frame: u32,
    cb_save_regs: u32,
    uses_alloca: bool,
    is_naked: bool,
    encoded_local_base: u8,
}

#[derive(Clone, Copy, Debug)]
enum LocalLoc {
    BpRel(i32),
    FramePtrRel(i32),
    RegRel(u16, i32),
}

#[derive(Clone, Debug)]
struct PendingLocal {
    name: String,
    type_index: TypeIndex,
    is_param: bool,
    is_optimized_out: bool,
    location: Option<(LocalLoc, bool)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeKind {
    Procedure,
    InlineSite,
    Other,
}

struct ActiveProc {
    vma: u64,
    offset: PdbInternalSectionOffset,
    name: String,
    type_index: Option<TypeIndex>,
    noreturn: bool,
    frame_proc: Option<FrameProcInfo>,
    param_names: Vec<String>,
    pending_locals: Vec<(String, TypeIndex, LocalLoc)>,
}

/// Normalize a PDB symbol name (decorated `?` or undecorated MSVC display name).
pub(crate) fn normalize_pdb_name(raw: &str) -> String {
    if raw.starts_with('?') {
        if let Some(demangled) = crate::demangle::demangle_name(raw) {
            return demangled;
        }
    }
    crate::demangle::normalize_msvc_name(raw)
}

/// Walk the global symbol stream + all DBI module streams of an opened `.pdb`.
pub fn walk_all(
    pdb: &mut pdb::PDB<'_, std::fs::File>,
    image_base: u64,
    arch: object::Architecture,
    id_finder: Option<&IdFinder<'_>>,
    type_builder: Option<&PdbTypeBuilder<'_>>,
) -> PdbWalkResult {
    let mut result = PdbWalkResult::default();
    let Ok(address_map) = pdb.address_map() else {
        return result;
    };

    let mut funcs_by_vma: BTreeMap<u64, PdbFuncFact> = BTreeMap::new();
    let mut globals_by_vma: BTreeMap<u64, PdbGlobalFact> = BTreeMap::new();

    if let Ok(symbols) = pdb.global_symbols() {
        walk_global_stream(&symbols, &address_map, image_base, &mut funcs_by_vma, &mut globals_by_vma);
    }

    if let Ok(dbi) = pdb.debug_information() {
        if let Ok(mut modules) = dbi.modules() {
            while let Ok(Some(module)) = modules.next() {
                let Ok(Some(info)) = pdb.module_info(&module) else {
                    continue;
                };
                walk_module_stream(
                    &info,
                    &address_map,
                    image_base,
                    arch,
                    id_finder,
                    type_builder,
                    &mut funcs_by_vma,
                    &mut globals_by_vma,
                    &mut result.locals,
                    &mut result.inline_sites,
                );
            }
        }
    }

    result.functions = funcs_by_vma.into_values().collect();
    result.globals = globals_by_vma.into_values().collect();
    result
}

fn walk_global_stream(
    symbols: &pdb::SymbolTable<'_>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    funcs: &mut BTreeMap<u64, PdbFuncFact>,
    globals: &mut BTreeMap<u64, PdbGlobalFact>,
) {
    let mut iter = symbols.iter();
    while let Ok(Some(symbol)) = iter.next() {
        let Ok(data) = symbol.parse() else {
            continue;
        };
        match data {
            SymbolData::Public(pubsym) if pubsym.function => {
                let Some(vma) = resolve_vma(pubsym.offset, address_map, image_base) else {
                    continue;
                };
                let name = normalize_pdb_name(&pubsym.name.to_string());
                if name.is_empty() {
                    continue;
                }
                funcs.entry(vma).or_insert_with(|| PdbFuncFact {
                    vma,
                    name,
                    type_index: None,
                    param_names: Vec::new(),
                    noreturn: false,
                    from_proc: false,
                });
            }
            SymbolData::Procedure(proc) => {
                let Some(vma) = resolve_vma(proc.offset, address_map, image_base) else {
                    continue;
                };
                let name = normalize_pdb_name(&proc.name.to_string());
                if name.is_empty() {
                    continue;
                }
                let type_index = (proc.type_index.0 != 0).then_some(proc.type_index);
                insert_proc_fact(
                    funcs,
                    PdbFuncFact {
                        vma,
                        name,
                        type_index,
                        param_names: Vec::new(),
                        noreturn: proc.flags.never,
                        from_proc: true,
                    },
                );
            }
            SymbolData::Data(d) => {
                record_global_data(&d, address_map, image_base, globals);
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_module_stream(
    info: &pdb::ModuleInfo<'_>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    arch: object::Architecture,
    id_finder: Option<&IdFinder<'_>>,
    type_builder: Option<&PdbTypeBuilder<'_>>,
    funcs: &mut BTreeMap<u64, PdbFuncFact>,
    globals: &mut BTreeMap<u64, PdbGlobalFact>,
    locals_out: &mut Vec<PdbLocalFact>,
    inline_sites_out: &mut Vec<InlineSiteFact>,
) {
    let mut module_inlinees: HashMap<IdIndex, Inlinee<'_>> = HashMap::new();
    if let Ok(mut inl_iter) = info.inlinees() {
        while let Ok(Some(inl)) = inl_iter.next() {
            module_inlinees.entry(inl.index()).or_insert(inl);
        }
    }

    let Ok(mut symbols) = info.symbols() else {
        return;
    };

    let mut scope_stack: Vec<ScopeKind> = Vec::new();
    let mut inline_depth: u16 = 0;
    let mut current_proc: Option<ActiveProc> = None;
    let mut last_local: Option<PendingLocal> = None;

    while let Ok(Some(symbol)) = symbols.next() {
        let raw_kind = symbol.raw_kind();
        let raw_bytes = symbol.raw_bytes();

        if symbol.ends_scope() {
            flush_pending_local(&mut last_local, current_proc.as_mut());
            match scope_stack.pop() {
                Some(ScopeKind::Procedure) => {
                    if let Some(proc) = current_proc.take() {
                        finish_proc(proc, arch, funcs, locals_out);
                    }
                }
                Some(ScopeKind::InlineSite) => {
                    inline_depth = inline_depth.saturating_sub(1);
                }
                _ => {}
            }
            continue;
        }

        // Defrange records immediately follow their owning `S_LOCAL`.
        match raw_kind {
            S_DEFRANGE_FRAMEPOINTER_REL | S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => {
                if inline_depth == 0 {
                    if let Some(off) = decode_defrange_fp_rel(raw_bytes) {
                        let full = raw_kind == S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE;
                        attach_defrange(&mut last_local, LocalLoc::FramePtrRel(off), full);
                    }
                }
                continue;
            }
            S_DEFRANGE_REGISTER_REL => {
                if inline_depth == 0 {
                    if let Some((reg, off)) = decode_defrange_reg_rel(raw_bytes) {
                        attach_defrange(&mut last_local, LocalLoc::RegRel(reg, off), false);
                    }
                }
                continue;
            }
            _ => {
                flush_pending_local(&mut last_local, current_proc.as_mut());
            }
        }

        if raw_kind == S_FRAMEPROC {
            if inline_depth == 0 {
                if let (Some(proc), Some(fp)) = (current_proc.as_mut(), decode_frameproc(raw_bytes)) {
                    proc.frame_proc = Some(fp);
                }
            }
            continue;
        }

        if matches!(raw_kind, S_BPREL32 | S_BPREL32_ST) {
            if inline_depth == 0 {
                if let (Some(proc), Some((off, ti, name))) =
                    (current_proc.as_mut(), decode_bprel32(raw_bytes))
                {
                    if !name.is_empty() {
                        if off >= 8 {
                            proc.param_names.push(name);
                        } else if off < 0 {
                            proc.pending_locals.push((name, ti, LocalLoc::BpRel(off)));
                        }
                    }
                }
            }
            continue;
        }

        let Ok(data) = symbol.parse() else {
            if symbol.starts_scope() {
                scope_stack.push(ScopeKind::Other);
            }
            continue;
        };

        match data {
            SymbolData::Procedure(proc) => {
                scope_stack.push(ScopeKind::Procedure);
                if let Some(prev) = current_proc.take() {
                    finish_proc(prev, arch, funcs, locals_out);
                }
                let Some(vma) = resolve_vma(proc.offset, address_map, image_base) else {
                    continue;
                };
                let name = normalize_pdb_name(&proc.name.to_string());
                let type_index = resolve_proc_type_index(raw_kind, proc.type_index, id_finder);
                current_proc = Some(ActiveProc {
                    vma,
                    offset: proc.offset,
                    name,
                    type_index,
                    noreturn: proc.flags.never,
                    frame_proc: None,
                    param_names: Vec::new(),
                    pending_locals: Vec::new(),
                });
            }
            SymbolData::InlineSite(site) => {
                let depth = inline_depth;
                inline_depth = inline_depth.saturating_add(1);
                scope_stack.push(ScopeKind::InlineSite);
                if let Some(proc) = current_proc.as_ref() {
                    let inlinee_name = resolve_inlinee_name(site.inlinee, id_finder, type_builder);
                    let ranges = extract_inline_ranges(
                        proc.offset,
                        &site,
                        module_inlinees.get(&site.inlinee),
                        address_map,
                        image_base,
                    );
                    if !inlinee_name.is_empty() && !ranges.is_empty() {
                        inline_sites_out.push(InlineSiteFact {
                            caller_addr: proc.vma,
                            inlinee_id: kuna_decomp::kuna_inlinesites::InlineeId::Pdb(site.inlinee.0),
                            inlinee_name,
                            depth,
                            ranges,
                        });
                    }
                }
            }
            SymbolData::Local(local) => {
                if inline_depth == 0 {
                    if let Some(proc) = current_proc.as_mut() {
                        let name = local.name.to_string().into_owned();
                        if !name.is_empty() {
                            if local.flags.isparam {
                                proc.param_names.push(name.clone());
                            }
                            last_local = Some(PendingLocal {
                                name,
                                type_index: local.type_index,
                                is_param: local.flags.isparam,
                                is_optimized_out: local.flags.isoptimizedout,
                                location: None,
                            });
                        }
                    }
                }
            }
            SymbolData::RegisterRelative(rr) => {
                if inline_depth == 0 {
                    if let Some(proc) = current_proc.as_mut() {
                        let name = rr.name.to_string().into_owned();
                        if !name.is_empty() {
                            proc.pending_locals
                                .push((name, rr.type_index, LocalLoc::RegRel(rr.register.0, rr.offset)));
                        }
                    }
                }
            }
            SymbolData::Data(d) => {
                record_global_data(&d, address_map, image_base, globals);
            }
            _ => {
                if symbol.starts_scope() {
                    scope_stack.push(ScopeKind::Other);
                }
            }
        }
    }

    flush_pending_local(&mut last_local, current_proc.as_mut());
    if let Some(proc) = current_proc.take() {
        finish_proc(proc, arch, funcs, locals_out);
    }
}

fn attach_defrange(slot: &mut Option<PendingLocal>, loc: LocalLoc, full_scope: bool) {
    let Some(pending) = slot.as_mut() else {
        return;
    };
    match pending.location {
        None => pending.location = Some((loc, full_scope)),
        Some((_, false)) if full_scope => pending.location = Some((loc, true)),
        _ => {}
    }
}

fn flush_pending_local(slot: &mut Option<PendingLocal>, proc: Option<&mut ActiveProc>) {
    let Some(pending) = slot.take() else {
        return;
    };
    if pending.is_optimized_out || pending.is_param {
        return;
    }
    let (Some(proc), Some((loc, _))) = (proc, pending.location) else {
        return;
    };
    proc.pending_locals.push((pending.name, pending.type_index, loc));
}

fn finish_proc(
    proc: ActiveProc,
    arch: object::Architecture,
    funcs: &mut BTreeMap<u64, PdbFuncFact>,
    locals_out: &mut Vec<PdbLocalFact>,
) {
    if !proc.name.is_empty() {
        insert_proc_fact(
            funcs,
            PdbFuncFact {
                vma: proc.vma,
                name: proc.name,
                type_index: proc.type_index,
                param_names: proc.param_names,
                noreturn: proc.noreturn,
                from_proc: true,
            },
        );
    }

    let mut seen_offsets: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for (name, type_index, loc) in proc.pending_locals {
        let Some(stack_offset) = translate_local_offset(arch, proc.frame_proc, loc) else {
            continue;
        };
        // Only emit negative stack-frame locals; positive offsets are incoming/shadow args.
        if stack_offset >= 0 || !seen_offsets.insert(stack_offset) {
            continue;
        }
        locals_out.push(PdbLocalFact {
            func_addr: proc.vma,
            name,
            type_index,
            stack_offset,
        });
    }
}

fn is_specific_public_name(name: &str) -> bool {
    name.contains("deleting_destructor")
        || name.contains("adjustor")
        || name.contains("vtordisp")
        || name.contains("vcall")
}

fn insert_proc_fact(funcs: &mut BTreeMap<u64, PdbFuncFact>, mut fact: PdbFuncFact) {
    match funcs.get_mut(&fact.vma) {
        None => {
            funcs.insert(fact.vma, fact);
        }
        Some(existing) => {
            if !existing.from_proc {
                if is_specific_public_name(&existing.name) && !is_specific_public_name(&fact.name) {
                    fact.name = existing.name.clone();
                }
                *existing = fact;
            } else {
                if existing.type_index.is_none() && fact.type_index.is_some() {
                    existing.type_index = fact.type_index;
                }
                if existing.param_names.is_empty() && !fact.param_names.is_empty() {
                    existing.param_names = fact.param_names;
                }
                existing.noreturn |= fact.noreturn;
            }
        }
    }
}

fn record_global_data(
    d: &pdb::DataSymbol<'_>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    globals: &mut BTreeMap<u64, PdbGlobalFact>,
) {
    let Some(vma) = resolve_vma(d.offset, address_map, image_base) else {
        return;
    };
    if vma == image_base {
        return;
    }
    let raw_name = d.name.to_string();
    if is_skipped_global_name(&raw_name) {
        return;
    }
    let name = normalize_pdb_name(&raw_name);
    if name.is_empty() {
        return;
    }
    match globals.get_mut(&vma) {
        None => {
            globals.insert(
                vma,
                PdbGlobalFact { vma, name, type_index: d.type_index, global: d.global },
            );
        }
        Some(existing) if !existing.global && d.global => {
            *existing = PdbGlobalFact { vma, name, type_index: d.type_index, global: d.global };
        }
        _ => {}
    }
}

fn is_skipped_global_name(raw: &str) -> bool {
    raw.is_empty()
        || raw.contains("`vftable'")
        || raw.contains("`vbtable'")
        || raw.contains("`RTTI ")
        || raw.contains("`string'")
        || raw.starts_with("??_7")
        || raw.starts_with("??_8")
        || raw.starts_with("??_C")
        || raw.starts_with("??_R")
        || raw.starts_with("__imp_")
        || raw.starts_with("$")
        || raw.starts_with("?")
}

fn resolve_vma(
    offset: PdbInternalSectionOffset,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
) -> Option<u64> {
    let rva = offset.to_rva(address_map)?;
    image_base.checked_add(u64::from(rva.0))
}

fn resolve_proc_type_index(
    raw_kind: u16,
    raw_ti: TypeIndex,
    id_finder: Option<&IdFinder<'_>>,
) -> Option<TypeIndex> {
    if matches!(raw_kind, S_LPROC32_ID | S_GPROC32_ID | S_LPROC32_DPC_ID) {
        let finder = id_finder?;
        let item = finder.find(IdIndex(raw_ti.0)).ok()?;
        return match item.parse().ok()? {
            IdData::Function(f) => (f.function_type.0 != 0).then_some(f.function_type),
            IdData::MemberFunction(mf) => (mf.function_type.0 != 0).then_some(mf.function_type),
            _ => None,
        };
    }
    (raw_ti.0 != 0).then_some(raw_ti)
}

fn resolve_inlinee_name(
    inlinee: IdIndex,
    id_finder: Option<&IdFinder<'_>>,
    type_builder: Option<&PdbTypeBuilder<'_>>,
) -> String {
    let Some(finder) = id_finder else {
        return String::new();
    };
    let Ok(item) = finder.find(inlinee) else {
        return String::new();
    };
    let Ok(data) = item.parse() else {
        return String::new();
    };
    match data {
        IdData::Function(f) => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(scope_id) = f.scope {
                if let Ok(scope_item) = finder.find(scope_id) {
                    if let Ok(IdData::String(s)) = scope_item.parse() {
                        let sname = s.name.to_string();
                        if !sname.is_empty() {
                            parts.push(sname.into_owned());
                        }
                    }
                }
            }
            let fname = f.name.to_string();
            if !fname.is_empty() {
                parts.push(fname.into_owned());
            }
            normalize_pdb_name(&parts.join("::"))
        }
        IdData::MemberFunction(mf) => {
            let mname = mf.name.to_string();
            let parent = type_builder.and_then(|tb| tb.type_name(mf.parent));
            let full = match parent {
                Some(p) if !p.is_empty() => format!("{p}::{mname}"),
                _ => mname.into_owned(),
            };
            normalize_pdb_name(&full)
        }
        _ => String::new(),
    }
}

fn extract_inline_ranges(
    proc_offset: PdbInternalSectionOffset,
    site: &pdb::InlineSiteSymbol<'_>,
    inlinee: Option<&Inlinee<'_>>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    if let Some(inl) = inlinee {
        let mut lines = inl.lines(proc_offset, site);
        while let Ok(Some(line)) = lines.next() {
            let Some(len) = line.length.filter(|&l| l > 0) else {
                continue;
            };
            let Some(start) = resolve_vma(line.offset, address_map, image_base) else {
                continue;
            };
            if let Some(end) = start.checked_add(u64::from(len)) {
                ranges.push((start, end));
            }
        }
    }
    if ranges.is_empty() {
        extract_annotation_ranges(proc_offset, site, address_map, image_base, &mut ranges);
    }
    coalesce_ranges(&mut ranges);
    ranges
}

fn extract_annotation_ranges(
    proc_offset: PdbInternalSectionOffset,
    site: &pdb::InlineSiteSymbol<'_>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    ranges: &mut Vec<(u64, u64)>,
) {
    use pdb::BinaryAnnotation;
    let mut code_offset = proc_offset;
    let mut code_offset_base: u32 = 0;
    let mut last_start: Option<PdbInternalSectionOffset> = None;
    let mut iter = site.annotations.iter();
    while let Ok(Some(op)) = iter.next() {
        match op {
            BinaryAnnotation::CodeOffset(off) => code_offset.offset = off,
            BinaryAnnotation::ChangeCodeOffsetBase(base) => code_offset_base = base,
            BinaryAnnotation::ChangeCodeOffset(delta) => {
                code_offset.offset = code_offset.offset.wrapping_add(delta);
                let cur = PdbInternalSectionOffset::new(
                    code_offset.section,
                    code_offset.offset.wrapping_add(code_offset_base),
                );
                if let Some(prev) = last_start.replace(cur) {
                    push_offset_span(prev, cur.offset.saturating_sub(prev.offset), address_map, image_base, ranges);
                }
            }
            BinaryAnnotation::ChangeCodeLength(len) => {
                if let Some(prev) = last_start.take() {
                    push_offset_span(prev, len, address_map, image_base, ranges);
                }
                code_offset.offset = code_offset.offset.wrapping_add(len);
            }
            BinaryAnnotation::ChangeCodeOffsetAndLineOffset(delta, _) => {
                code_offset.offset = code_offset.offset.wrapping_add(delta);
                let cur = PdbInternalSectionOffset::new(
                    code_offset.section,
                    code_offset.offset.wrapping_add(code_offset_base),
                );
                if let Some(prev) = last_start.replace(cur) {
                    push_offset_span(prev, cur.offset.saturating_sub(prev.offset), address_map, image_base, ranges);
                }
            }
            BinaryAnnotation::ChangeCodeLengthAndCodeOffset(len, delta) => {
                code_offset.offset = code_offset.offset.wrapping_add(delta);
                let cur = PdbInternalSectionOffset::new(
                    code_offset.section,
                    code_offset.offset.wrapping_add(code_offset_base),
                );
                if let Some(prev) = last_start.take() {
                    push_offset_span(prev, cur.offset.saturating_sub(prev.offset), address_map, image_base, ranges);
                }
                push_offset_span(cur, len, address_map, image_base, ranges);
            }
            _ => {}
        }
    }
}

fn push_offset_span(
    start_off: PdbInternalSectionOffset,
    len: u32,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    ranges: &mut Vec<(u64, u64)>,
) {
    if len == 0 {
        return;
    }
    if let Some(start) = resolve_vma(start_off, address_map, image_base) {
        if let Some(end) = start.checked_add(u64::from(len)) {
            ranges.push((start, end));
        }
    }
}

fn coalesce_ranges(ranges: &mut Vec<(u64, u64)>) {
    if ranges.len() <= 1 {
        return;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    *ranges = merged;
}

fn translate_local_offset(
    arch: object::Architecture,
    frame: Option<FrameProcInfo>,
    loc: LocalLoc,
) -> Option<i64> {
    if frame.is_some_and(|f| f.uses_alloca || f.is_naked) {
        return None;
    }
    match arch {
        object::Architecture::X86_64 => match loc {
            LocalLoc::RegRel(CV_ALLREG_VFRAME, off) => Some(i64::from(off) + 8),
            LocalLoc::RegRel(CV_AMD64_RSP, off) => {
                let fp = frame?;
                Some(i64::from(off) - i64::from(fp.cb_frame) - i64::from(fp.cb_save_regs))
            }
            LocalLoc::FramePtrRel(off) => {
                let fp = frame?;
                if fp.encoded_local_base == 1 {
                    Some(i64::from(off) - i64::from(fp.cb_frame) - i64::from(fp.cb_save_regs))
                } else {
                    None
                }
            }
            LocalLoc::RegRel(CV_AMD64_RBP, _) | LocalLoc::BpRel(_) | LocalLoc::RegRel(_, _) => None,
        },
        object::Architecture::I386 => match loc {
            LocalLoc::BpRel(off) | LocalLoc::RegRel(CV_REG_EBP, off) => Some(i64::from(off) - 4),
            LocalLoc::RegRel(CV_REG_ESP, off) => {
                let fp = frame?;
                Some(i64::from(off) - i64::from(fp.cb_frame) - i64::from(fp.cb_save_regs))
            }
            LocalLoc::FramePtrRel(off) => {
                let fp = frame?;
                match fp.encoded_local_base {
                    1 => Some(i64::from(off) - i64::from(fp.cb_frame) - i64::from(fp.cb_save_regs)),
                    2 => Some(i64::from(off) - 4),
                    _ => None,
                }
            }
            LocalLoc::RegRel(_, _) => None,
        },
        _ => None,
    }
}

/// Decode `S_BPREL32` (`0x110b`) or `S_BPREL32_ST` (`0x1006`) directly from raw symbol bytes.
pub(crate) fn decode_bprel32(raw: &[u8]) -> Option<(i32, TypeIndex, String)> {
    if raw.len() < 11 {
        return None;
    }
    let kind = u16::from_le_bytes([raw[0], raw[1]]);
    let offset = i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
    let type_index = TypeIndex(u32::from_le_bytes([raw[6], raw[7], raw[8], raw[9]]));
    let name = match kind {
        S_BPREL32 => {
            let rest = &raw[10..];
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(&rest[..end]).into_owned()
        }
        S_BPREL32_ST => {
            let len = raw[10] as usize;
            let rest = raw.get(11..11 + len)?;
            String::from_utf8_lossy(rest).into_owned()
        }
        _ => return None,
    };
    Some((offset, type_index, name))
}

/// Decode `S_FRAMEPROC` (`0x1012`) directly from raw symbol bytes.
fn decode_frameproc(raw: &[u8]) -> Option<FrameProcInfo> {
    if raw.len() < 28 {
        return None;
    }
    let kind = u16::from_le_bytes([raw[0], raw[1]]);
    if kind != S_FRAMEPROC {
        return None;
    }
    let cb_frame = u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
    let cb_save_regs = u32::from_le_bytes([raw[14], raw[15], raw[16], raw[17]]);
    let flags = u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]);
    Some(FrameProcInfo {
        cb_frame,
        cb_save_regs,
        uses_alloca: (flags & 0x0001) != 0,
        is_naked: (flags & 0x0080) != 0,
        encoded_local_base: ((flags >> 14) & 0x3) as u8,
    })
}

/// Decode `S_DEFRANGE_FRAMEPOINTER_REL` (`0x1142`) or
/// `S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE` (`0x1144`) directly from raw bytes.
pub(crate) fn decode_defrange_fp_rel(raw: &[u8]) -> Option<i32> {
    if raw.len() < 6 {
        return None;
    }
    let kind = u16::from_le_bytes([raw[0], raw[1]]);
    if !matches!(kind, S_DEFRANGE_FRAMEPOINTER_REL | S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE) {
        return None;
    }
    Some(i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]))
}

/// Decode `S_DEFRANGE_REGISTER_REL` (`0x1145`) directly from raw bytes.
pub(crate) fn decode_defrange_reg_rel(raw: &[u8]) -> Option<(u16, i32)> {
    if raw.len() < 10 {
        return None;
    }
    let kind = u16::from_le_bytes([raw[0], raw[1]]);
    if kind != S_DEFRANGE_REGISTER_REL {
        return None;
    }
    let base_reg = u16::from_le_bytes([raw[2], raw[3]]);
    let flags = u16::from_le_bytes([raw[4], raw[5]]);
    if (flags & 0x0001) != 0 {
        return None;
    }
    let offset = i32::from_le_bytes([raw[6], raw[7], raw[8], raw[9]]);
    Some((base_reg, offset))
}

/// Walk an opened `.pdb`'s global symbol stream, returning `(vma, name)` pairs.
pub fn walk_functions(pdb: &mut pdb::PDB<'_, std::fs::File>, image_base: u64) -> Vec<PdbFunc> {
    let mut out: Vec<PdbFunc> = Vec::new();
    let Ok(address_map) = pdb.address_map() else {
        return out;
    };
    if let Ok(symbols) = pdb.global_symbols() {
        collect_symbols(&symbols, &address_map, image_base, &mut out);
    }
    out
}

/// Walk every module stream of an opened `.pdb` and return its procedure
/// records, sorted and deduplicated.
pub fn walk_procedures(
    pdb: &mut pdb::PDB<'_, std::fs::File>,
    image_base: u64,
) -> Vec<PdbProcedure> {
    let mut out: Vec<PdbProcedure> = Vec::new();
    let (Ok(address_map), Ok(dbi)) = (pdb.address_map(), pdb.debug_information()) else {
        return out;
    };
    let Ok(mut modules) = dbi.modules() else {
        return out;
    };
    while let Ok(Some(module)) = modules.next() {
        let Ok(Some(info)) = pdb.module_info(&module) else {
            continue;
        };
        let Ok(mut symbols) = info.symbols() else {
            continue;
        };
        while let Ok(Some(symbol)) = symbols.next() {
            if !PROCEDURE_KINDS.contains(&symbol.raw_kind()) {
                continue;
            }
            let Ok(SymbolData::Procedure(proc)) = symbol.parse() else {
                continue;
            };
            let Some(internal) = proc.offset.to_internal_rva(&address_map) else {
                continue;
            };
            let Some(rva) = internal.to_rva(&address_map) else {
                continue;
            };
            let Some(start) = image_base.checked_add(u64::from(rva.0)) else {
                continue;
            };
            let end = contiguous_length(&address_map, internal, rva, proc.len)
                .and_then(|len| start.checked_add(len));
            out.push(PdbProcedure { start, end });
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn contiguous_length(
    map: &pdb::AddressMap<'_>,
    internal: pdb::PdbInternalRva,
    rva: pdb::Rva,
    len: u32,
) -> Option<u64> {
    let internal_end = pdb::PdbInternalRva(internal.0.checked_add(len)?);
    let mut ranges = map.rva_ranges(internal..internal_end);
    let only = ranges.next()?;
    let whole = ranges.next().is_none()
        && only.start == rva
        && only.end.0.checked_sub(only.start.0) == Some(len);
    (len != 0 && whole).then_some(u64::from(len))
}

fn collect_symbols(
    symbols: &pdb::SymbolTable<'_>,
    address_map: &pdb::AddressMap<'_>,
    image_base: u64,
    out: &mut Vec<PdbFunc>,
) {
    let mut iter = symbols.iter();
    while let Ok(Some(symbol)) = iter.next() {
        let Ok(data) = symbol.parse() else {
            continue;
        };
        match data {
            SymbolData::Public(pubsym) if pubsym.function => {
                if let Some(rva) = pubsym.offset.to_rva(address_map) {
                    out.push(PdbFunc {
                        vma: image_base.wrapping_add(u64::from(rva.0)),
                        name: pubsym.name.to_string().into_owned(),
                    });
                }
            }
            SymbolData::Procedure(proc) => {
                if let Some(rva) = proc.offset.to_rva(address_map) {
                    out.push(PdbFunc {
                        vma: image_base.wrapping_add(u64::from(rva.0)),
                        name: proc.name.to_string().into_owned(),
                    });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdb_func_eq() {
        let a = PdbFunc { vma: 0x401000, name: "main".into() };
        let b = PdbFunc { vma: 0x401000, name: "main".into() };
        assert_eq!(a, b);
    }

    #[test]
    fn decode_raw_symbol_helpers() {
        // S_BPREL32: kind=0x110b, offset=-16, type=0x74, name="count\0"
        let mut bp = Vec::new();
        bp.extend_from_slice(&S_BPREL32.to_le_bytes());
        bp.extend_from_slice(&(-16i32).to_le_bytes());
        bp.extend_from_slice(&0x74u32.to_le_bytes());
        bp.extend_from_slice(b"count\0");
        assert_eq!(decode_bprel32(&bp), Some((-16, TypeIndex(0x74), "count".to_string())));

        // S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: kind=0x1144, offset=0x20
        let mut fp = Vec::new();
        fp.extend_from_slice(&S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE.to_le_bytes());
        fp.extend_from_slice(&32i32.to_le_bytes());
        assert_eq!(decode_defrange_fp_rel(&fp), Some(32));

        // S_DEFRANGE_REGISTER_REL: kind=0x1145, reg=335 (RSP), flags=0, offset=0x30
        let mut rr = Vec::new();
        rr.extend_from_slice(&S_DEFRANGE_REGISTER_REL.to_le_bytes());
        rr.extend_from_slice(&CV_AMD64_RSP.to_le_bytes());
        rr.extend_from_slice(&0u16.to_le_bytes());
        rr.extend_from_slice(&0x30i32.to_le_bytes());
        assert_eq!(decode_defrange_reg_rel(&rr), Some((CV_AMD64_RSP, 0x30)));

        // Spilled UDT member flag (bit 0) is rejected.
        rr[4] = 1;
        assert_eq!(decode_defrange_reg_rel(&rr), None);

        // S_FRAMEPROC: cbFrame=0x40, cbSaveRegs=0x10, encodedLocalBase=1 (RSP)
        let mut fr = vec![0u8; 28];
        fr[0..2].copy_from_slice(&S_FRAMEPROC.to_le_bytes());
        fr[2..6].copy_from_slice(&0x40u32.to_le_bytes());
        fr[14..18].copy_from_slice(&0x10u32.to_le_bytes());
        let flags: u32 = 1 << 14;
        fr[24..28].copy_from_slice(&flags.to_le_bytes());
        let info = decode_frameproc(&fr).unwrap();
        assert_eq!(info.cb_frame, 0x40);
        assert_eq!(info.cb_save_regs, 0x10);
        assert_eq!(info.encoded_local_base, 1);
        assert_eq!(
            translate_local_offset(
                object::Architecture::X86_64,
                Some(info),
                LocalLoc::RegRel(CV_AMD64_RSP, 0x20),
            ),
            Some(-0x30)
        );
    }

    #[test]
    fn procedures_carry_their_extent_or_none() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pe_pdbinterior_x86_64.pdb");
        let file = std::fs::File::open(path).expect("open the fixture pdb");
        let mut pdb = pdb::PDB::open(file).expect("parse the fixture pdb");
        let procs = walk_procedures(&mut pdb, 0x140000000);
        assert_eq!(procs.len(), 34, "{procs:#x?}");
        for (start, end) in [
            (0x1400011c0, Some(0x1400011f8)),
            (0x140001340, Some(0x140001378)),
            (0x140001540, None),
            (0x140001548, Some(0x140001568)),
            (0x140002008, Some(0x140002010)),
        ] {
            assert!(procs.contains(&PdbProcedure { start, end }), "{start:#x}: {procs:#x?}");
        }
    }
}
