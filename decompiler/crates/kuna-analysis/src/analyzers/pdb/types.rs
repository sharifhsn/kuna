//! PDB TPI (Type Information) -> kuna [`Datatype`] importer.
//!
//! Resolves forward references to their complete definitions in one pre-pass,
//! maps CodeView primitives, modifiers, pointers, arrays, enums, structs/classes,
//! unions, bitfields, base classes, vftable pointers, and function types into
//! the architecture's [`TypeFactory`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use pdb::{
    ArrayType, BitfieldType, ClassKind, ClassType, EnumerationType, FallibleIterator, Indirection,
    MemberFunctionType, PointerType, PrimitiveKind, PrimitiveType, ProcedureType, TypeData,
    TypeFinder, TypeIndex, TypeInformation, UnionType, Variant,
};

use kuna_base::types::{int4, uint4};
use kuna_decomp::dtype::{type_metatype, Datatype, TypeBitField, TypeFactory, TypeField};
use kuna_decomp::fspec::PrototypePieces;

use crate::dwarf::{byte_exact_bitfield, group_bitfields};

const MAX_TYPE_DEPTH: u32 = 64;
const MAX_FIELDLIST_CONTINUATIONS: usize = 256;
const MAX_NAME_ATTEMPTS: u32 = 4;

const KIND_CLASS: u8 = 0;
const KIND_UNION: u8 = 1;
const KIND_ENUM: u8 = 2;

/// Stateful TPI -> kuna [`TypeFactory`] builder with forward-ref resolution,
/// result caching, and cycle guards.
pub struct PdbTypeBuilder<'a> {
    types: &'a dyn TypeFactory,
    word_size: uint4,
    ptr_size: int4,
    finder: TypeFinder<'a>,
    fwd_to_def: HashMap<TypeIndex, TypeIndex>,
    cache: HashMap<TypeIndex, Option<Rc<Datatype>>>,
    in_progress: HashSet<TypeIndex>,
    populating_names: HashSet<String>,
    depth: u32,
}

impl<'a> PdbTypeBuilder<'a> {
    /// Build a TPI type builder: populates the [`TypeFinder`] and two-step
    /// forward-reference map (`unique_name` first, then `(kind, name)`) in a
    /// single linear pass over `tpi`.
    pub fn new(tpi: &'a TypeInformation<'_>, types: &'a dyn TypeFactory, word_size: uint4) -> Self {
        let mut finder = tpi.finder();
        let mut def_by_unique: HashMap<String, (TypeIndex, bool)> = HashMap::new();
        let mut def_by_name: HashMap<(u8, String), (TypeIndex, bool)> = HashMap::new();
        let mut fwds: Vec<(TypeIndex, u8, String, Option<String>)> = Vec::new();

        let mut iter = tpi.iter();
        while let Ok(Some(item)) = iter.next() {
            finder.update(&iter);
            let idx = item.index();
            let Ok(data) = item.parse() else {
                continue;
            };
            match data {
                TypeData::Class(c) => {
                    let name = c.name.to_string().into_owned();
                    let unique = c.unique_name.map(|u| u.to_string().into_owned());
                    if c.properties.forward_reference() {
                        fwds.push((idx, KIND_CLASS, name, unique));
                    } else {
                        let rich = c.size > 0 && c.fields.is_some();
                        record_def(&mut def_by_unique, &mut def_by_name, KIND_CLASS, name, unique, idx, rich);
                    }
                }
                TypeData::Union(u) => {
                    let name = u.name.to_string().into_owned();
                    let unique = u.unique_name.map(|s| s.to_string().into_owned());
                    if u.properties.forward_reference() {
                        fwds.push((idx, KIND_UNION, name, unique));
                    } else {
                        let rich = u.size > 0;
                        record_def(&mut def_by_unique, &mut def_by_name, KIND_UNION, name, unique, idx, rich);
                    }
                }
                TypeData::Enumeration(e) => {
                    let name = e.name.to_string().into_owned();
                    let unique = e.unique_name.map(|s| s.to_string().into_owned());
                    if e.properties.forward_reference() {
                        fwds.push((idx, KIND_ENUM, name, unique));
                    } else {
                        let rich = e.count > 0;
                        record_def(&mut def_by_unique, &mut def_by_name, KIND_ENUM, name, unique, idx, rich);
                    }
                }
                _ => {}
            }
        }

        let mut fwd_to_def = HashMap::new();
        for (fwd_idx, tag, name, unique) in fwds {
            let resolved = unique
                .as_deref()
                .filter(|u| !u.is_empty())
                .and_then(|u| def_by_unique.get(u).map(|&(ti, _)| ti))
                .or_else(|| {
                    (!name.is_empty())
                        .then(|| def_by_name.get(&(tag, name)).map(|&(ti, _)| ti))
                        .flatten()
                });
            if let Some(def_idx) = resolved {
                if def_idx != fwd_idx {
                    fwd_to_def.insert(fwd_idx, def_idx);
                }
            }
        }

        let ptr_size = types.get_size_of_pointer().max(1);
        Self {
            types,
            word_size,
            ptr_size,
            finder,
            fwd_to_def,
            cache: HashMap::new(),
            in_progress: HashSet::new(),
            populating_names: HashSet::new(),
            depth: 0,
        }
    }

    /// Resolve a TPI [`TypeIndex`] to an interned kuna [`Datatype`].
    pub fn resolve_type(&mut self, raw_idx: TypeIndex) -> Option<Rc<Datatype>> {
        let idx = self.fwd_to_def.get(&raw_idx).copied().unwrap_or(raw_idx);
        if let Some(cached) = self.cache.get(&idx) {
            return cached.clone();
        }
        if self.depth >= MAX_TYPE_DEPTH || !self.in_progress.insert(idx) {
            return None;
        }
        self.depth += 1;
        let built = self.resolve_type_uncached(idx);
        self.depth -= 1;
        self.in_progress.remove(&idx);
        self.cache.insert(idx, built.clone());
        if raw_idx != idx {
            self.cache.insert(raw_idx, built.clone());
        }
        built
    }

    /// Read the raw type name for a TPI class/union/enum record (used to qualify
    /// `MemberFunctionId` names when resolving IPI inlinees).
    pub fn type_name(&self, raw_idx: TypeIndex) -> Option<String> {
        let idx = self.fwd_to_def.get(&raw_idx).copied().unwrap_or(raw_idx);
        let item = self.finder.find(idx).ok()?;
        let data = item.parse().ok()?;
        data.name().map(|n| n.to_string().into_owned())
    }

    /// Build a [`PrototypePieces`] + optional calling-convention prototype model
    /// from a TPI `Procedure` or `MemberFunction` index.
    pub fn build_prototype(
        &mut self,
        func_name: &str,
        type_idx: TypeIndex,
        param_names: &[String],
        is_32bit_x86: bool,
    ) -> Option<(PrototypePieces, Option<&'static str>)> {
        let item = self.finder.find(type_idx).ok()?;
        let data = item.parse().ok()?;
        match data {
            TypeData::Procedure(p) => self.build_procedure_proto(func_name, &p, param_names, is_32bit_x86),
            TypeData::MemberFunction(m) => {
                self.build_member_fn_proto(func_name, &m, param_names, is_32bit_x86)
            }
            _ => None,
        }
    }

    fn resolve_type_uncached(&mut self, idx: TypeIndex) -> Option<Rc<Datatype>> {
        let item = self.finder.find(idx).ok()?;
        let data = item.parse().ok()?;
        match data {
            TypeData::Primitive(p) => self.build_primitive(p),
            TypeData::Modifier(m) => self.resolve_type(m.underlying_type),
            TypeData::Pointer(p) => self.build_pointer(&p),
            TypeData::Array(a) => self.build_array(&a),
            TypeData::Enumeration(e) => self.build_enum(idx, &e),
            TypeData::Class(c) => self.build_class(idx, &c),
            TypeData::Union(u) => self.build_union(idx, &u),
            TypeData::Procedure(p) => {
                let (pieces, _) = self.build_procedure_proto("", &p, &[], false)?;
                self.types.get_type_code_proto(&pieces).ok()
            }
            TypeData::MemberFunction(m) => {
                let (pieces, _) = self.build_member_fn_proto("", &m, &[], false)?;
                self.types.get_type_code_proto(&pieces).ok()
            }
            _ => None,
        }
    }

    fn build_primitive(&self, p: PrimitiveType) -> Option<Rc<Datatype>> {
        let base = match p.kind {
            PrimitiveKind::NoType => None,
            PrimitiveKind::Void => self.types.get_type_void().ok(),
            PrimitiveKind::Char | PrimitiveKind::RChar => {
                self.types.get_type_char(self.types.get_size_of_char()).ok()
            }
            PrimitiveKind::UChar => self
                .types
                .get_type_char_signed("unsigned char", type_metatype::TYPE_UINT)
                .ok()
                .or_else(|| self.types.get_base(1, type_metatype::TYPE_UINT).ok()),
            PrimitiveKind::WChar | PrimitiveKind::RChar16 => self
                .types
                .get_type_char(2)
                .ok()
                .or_else(|| self.types.get_base(2, type_metatype::TYPE_UINT).ok()),
            PrimitiveKind::RChar32 => self
                .types
                .get_type_char(4)
                .ok()
                .or_else(|| self.types.get_base(4, type_metatype::TYPE_UINT).ok()),
            PrimitiveKind::I8 => self.types.get_base(1, type_metatype::TYPE_INT).ok(),
            PrimitiveKind::U8 => self.types.get_base(1, type_metatype::TYPE_UINT).ok(),
            PrimitiveKind::Short | PrimitiveKind::I16 => {
                self.types.get_base(2, type_metatype::TYPE_INT).ok()
            }
            PrimitiveKind::UShort | PrimitiveKind::U16 => {
                self.types.get_base(2, type_metatype::TYPE_UINT).ok()
            }
            PrimitiveKind::Long | PrimitiveKind::I32 | PrimitiveKind::HRESULT => {
                self.types.get_base(4, type_metatype::TYPE_INT).ok()
            }
            PrimitiveKind::ULong | PrimitiveKind::U32 => {
                self.types.get_base(4, type_metatype::TYPE_UINT).ok()
            }
            PrimitiveKind::Quad | PrimitiveKind::I64 => {
                self.types.get_base(8, type_metatype::TYPE_INT).ok()
            }
            PrimitiveKind::UQuad | PrimitiveKind::U64 => {
                self.types.get_base(8, type_metatype::TYPE_UINT).ok()
            }
            PrimitiveKind::Octa | PrimitiveKind::I128 => self
                .types
                .get_base(16, type_metatype::TYPE_INT)
                .ok()
                .or_else(|| self.types.get_base(16, type_metatype::TYPE_UNKNOWN).ok()),
            PrimitiveKind::UOcta | PrimitiveKind::U128 => self
                .types
                .get_base(16, type_metatype::TYPE_UINT)
                .ok()
                .or_else(|| self.types.get_base(16, type_metatype::TYPE_UNKNOWN).ok()),
            PrimitiveKind::F16 => self
                .types
                .get_base(2, type_metatype::TYPE_FLOAT)
                .ok()
                .or_else(|| self.types.get_base(2, type_metatype::TYPE_UNKNOWN).ok()),
            PrimitiveKind::F32 | PrimitiveKind::F32PP => {
                self.types.get_base(4, type_metatype::TYPE_FLOAT).ok()
            }
            PrimitiveKind::F48 => self.types.get_base(6, type_metatype::TYPE_UNKNOWN).ok(),
            PrimitiveKind::F64 => self.types.get_base(8, type_metatype::TYPE_FLOAT).ok(),
            PrimitiveKind::F80 => self
                .types
                .get_base(10, type_metatype::TYPE_FLOAT)
                .ok()
                .or_else(|| self.types.get_base(10, type_metatype::TYPE_UNKNOWN).ok()),
            PrimitiveKind::F128 => self
                .types
                .get_base(16, type_metatype::TYPE_FLOAT)
                .ok()
                .or_else(|| self.types.get_base(16, type_metatype::TYPE_UNKNOWN).ok()),
            PrimitiveKind::Bool8 => self.types.get_base(1, type_metatype::TYPE_BOOL).ok(),
            PrimitiveKind::Bool16 => self
                .types
                .get_base(2, type_metatype::TYPE_BOOL)
                .ok()
                .or_else(|| self.types.get_base(2, type_metatype::TYPE_UINT).ok()),
            PrimitiveKind::Bool32 => self
                .types
                .get_base(4, type_metatype::TYPE_BOOL)
                .ok()
                .or_else(|| self.types.get_base(4, type_metatype::TYPE_INT).ok()),
            PrimitiveKind::Bool64 => self
                .types
                .get_base(8, type_metatype::TYPE_BOOL)
                .ok()
                .or_else(|| self.types.get_base(8, type_metatype::TYPE_UINT).ok()),
            PrimitiveKind::Complex32 => self.types.get_base(8, type_metatype::TYPE_UNKNOWN).ok(),
            PrimitiveKind::Complex64 => self.types.get_base(16, type_metatype::TYPE_UNKNOWN).ok(),
            _ => None,
        };
        let Some(ind) = p.indirection else {
            return base;
        };
        let psize = match ind {
            Indirection::Near16 => 2,
            Indirection::Near32 | Indirection::Far16 | Indirection::Huge16 => 4,
            Indirection::Far32 => 6,
            Indirection::Near64 => 8,
            Indirection::Near128 => 16,
        };
        let pointee = base.or_else(|| self.types.get_type_void().ok())?;
        self.types.get_type_pointer(psize, pointee, self.word_size).ok()
    }

    fn build_pointer(&mut self, p: &PointerType) -> Option<Rc<Datatype>> {
        let psize = match p.attributes.size() {
            0 => self.ptr_size,
            s => s as int4,
        };
        if p.attributes.pointer_to_member() {
            if psize == self.ptr_size {
                let v = self.types.get_type_void().ok()?;
                return self.types.get_type_pointer(psize, v, self.word_size).ok();
            }
            if psize > 0 && psize <= 8 {
                return self.types.get_base(psize, type_metatype::TYPE_UNKNOWN).ok();
            }
            let u8_ty = self.types.get_base(1, type_metatype::TYPE_UINT).ok()?;
            return self.types.get_type_array(psize.max(1), u8_ty).ok();
        }
        let pointee = self
            .resolve_type(p.underlying_type)
            .or_else(|| self.types.get_type_void().ok())?;
        self.types.get_type_pointer(psize, pointee, self.word_size).ok()
    }

    fn build_array(&mut self, arr: &ArrayType) -> Option<Rc<Datatype>> {
        let elem = self.resolve_type(arr.element_type)?;
        let mut cur = elem;
        let mut prev_bytes = u64::try_from(cur.get_size()).ok().filter(|&s| s > 0)?;
        if arr.dimensions.is_empty() {
            return self.types.get_type_array(1, cur).ok();
        }
        // `pdb 0.8.0` reports cumulative byte sizes in `dimensions` (innermost first).
        for &dim_bytes in &arr.dimensions {
            let dim_bytes = u64::from(dim_bytes);
            let count = if dim_bytes == 0 {
                1u64
            } else {
                (dim_bytes / prev_bytes).max(1)
            };
            let count = i32::try_from(count).ok()?;
            cur = self.types.get_type_array(count, cur).ok()?;
            prev_bytes = u64::try_from(cur.get_size()).ok().filter(|&s| s > 0)?;
        }
        Some(cur)
    }

    fn build_enum(&mut self, idx: TypeIndex, e: &EnumerationType<'_>) -> Option<Rc<Datatype>> {
        let underlying = self.resolve_type(e.underlying_type);
        let size = underlying.as_ref().map(|t| t.get_size()).filter(|&s| s > 0).unwrap_or(4);
        let signed = underlying
            .as_ref()
            .is_some_and(|t| t.get_metatype() == type_metatype::TYPE_INT);
        let fallback = || {
            underlying.clone().or_else(|| {
                let meta = if signed { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT };
                self.types.get_base(size, meta).ok()
            })
        };
        if e.properties.forward_reference() || e.name.is_empty() {
            return fallback();
        }
        let raw_name = e.name.to_string();
        if is_anonymous_tag(&raw_name) {
            return fallback();
        }
        let mask: u64 = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        let mut nmap: BTreeMap<u64, String> = BTreeMap::new();
        for field in self.collect_field_list(e.fields) {
            if let TypeData::Enumerate(en) = field {
                let ename = en.name.to_string();
                if ename.is_empty() {
                    continue;
                }
                let v = variant_to_u64(en.value) & mask;
                nmap.entry(v).or_insert_with(|| ename.into_owned());
            }
        }
        if nmap.is_empty() {
            return fallback();
        }
        let meta = if signed {
            type_metatype::TYPE_ENUM_INT
        } else {
            type_metatype::TYPE_ENUM_UINT
        };
        let base_name = clean_type_name(&raw_name, idx, "anon_enum");
        if let Ok(Some(existing)) = self.types.find_by_name(&base_name) {
            if existing.is_enum_type() && existing.get_size() == size {
                return Some(existing);
            }
            return fallback();
        }
        let Ok(ct) = self.types.get_type_enum_sized(&base_name, size, meta) else {
            return fallback();
        };
        self.types.set_enum_values(&ct, nmap).ok().or_else(fallback)
    }

    fn build_class(&mut self, idx: TypeIndex, c: &ClassType<'_>) -> Option<Rc<Datatype>> {
        let want = type_metatype::TYPE_STRUCT;
        let fallback = match c.kind {
            ClassKind::Class => "anon_class",
            ClassKind::Struct => "anon_struct",
            ClassKind::Interface => "anon_interface",
        };
        let size = aggregate_size(c.size);
        let base_name = clean_type_name(&c.name.to_string(), idx, fallback);
        let name = resolve_record_name(self.types, &base_name, size, want)?;

        let existing = match self.types.find_by_name(&name) {
            Ok(Some(t)) if t.get_metatype() == want => Some(t),
            Ok(_) => None,
            Err(_) => return None,
        };
        if let Some(t) = &existing {
            if !t.is_incomplete() {
                return Some(Rc::clone(t));
            }
        }
        let shell = match existing {
            Some(t) => t,
            None => self
                .types
                .kuna_declare_record(&name, false)
                .ok()
                .filter(|t| t.get_metatype() == want)?,
        };

        // Pre-cache the shell so self-referential members (`Node *next`) resolve cleanly.
        self.cache.insert(idx, Some(Rc::clone(&shell)));

        let Some(size) = size else { return Some(shell) };
        if c.properties.forward_reference() {
            return Some(shell);
        }
        let Some(fields_ti) = c.fields else {
            return Some(shell);
        };
        if !self.populating_names.insert(name.clone()) {
            return Some(shell);
        }

        let items = self.collect_field_list(fields_ti);
        let (fields, bits) = self.build_struct_members(&items, size);
        self.populating_names.remove(&name);

        let align = derived_alignment(size, &fields, &bits);
        let extra = if bits.is_empty() { 0 } else { kuna_decomp::dtype::flags::has_bitfields };
        let done = self
            .types
            .set_fields_struct_raw(&shell, fields, bits, size, align, extra)
            .unwrap_or(shell);
        Some(done)
    }

    fn build_union(&mut self, idx: TypeIndex, u: &UnionType<'_>) -> Option<Rc<Datatype>> {
        let want = type_metatype::TYPE_UNION;
        let size = aggregate_size(u.size);
        let base_name = clean_type_name(&u.name.to_string(), idx, "anon_union");
        let name = resolve_record_name(self.types, &base_name, size, want)?;

        let existing = match self.types.find_by_name(&name) {
            Ok(Some(t)) if t.get_metatype() == want => Some(t),
            Ok(_) => None,
            Err(_) => return None,
        };
        if let Some(t) = &existing {
            if !t.is_incomplete() {
                return Some(Rc::clone(t));
            }
        }
        let shell = match existing {
            Some(t) => t,
            None => self
                .types
                .kuna_declare_record(&name, true)
                .ok()
                .filter(|t| t.get_metatype() == want)?,
        };

        self.cache.insert(idx, Some(Rc::clone(&shell)));

        let Some(size) = size else { return Some(shell) };
        if u.properties.forward_reference() {
            return Some(shell);
        }
        if !self.populating_names.insert(name.clone()) {
            return Some(shell);
        }

        let items = self.collect_field_list(u.fields);
        let mut fields: Vec<TypeField> = Vec::new();
        for item in &items {
            if let TypeData::Member(m) = item {
                let mname = m.name.to_string();
                if mname.is_empty() {
                    continue;
                }
                let Some(ty) = self.resolve_type(m.field_type) else {
                    continue;
                };
                if ty.get_metatype() == type_metatype::TYPE_VOID || ty.get_size() <= 0 {
                    continue;
                }
                fields.push(TypeField::new(fields.len() as int4, 0, mname.into_owned(), ty));
            }
        }
        self.populating_names.remove(&name);

        let align = derived_alignment(size, &fields, &[]);
        let done = self.types.set_fields_union_raw(&shell, fields, size, align).unwrap_or(shell);
        Some(done)
    }

    fn build_struct_members(
        &mut self,
        items: &[TypeData<'_>],
        struct_size: int4,
    ) -> (Vec<TypeField>, Vec<TypeBitField>) {
        let mut candidates: Vec<(int4, u8, int4, String, Rc<Datatype>)> = Vec::new();
        let mut raw_bits: Vec<(i64, int4, String, Rc<Datatype>)> = Vec::new();
        let end_bit = i64::from(struct_size) * 8;
        let mut seen_vbptr_offsets: HashSet<int4> = HashSet::new();

        for item in items {
            match item {
                TypeData::VirtualFunctionTablePointer(_) => {
                    // Never deref `vft.table` (`LF_VTSHAPE`/`LF_VFTABLE` return `UnimplementedTypeKind`).
                    if let Some(vft_ty) = self.vftable_ptr_type() {
                        let sz = vft_ty.get_size();
                        if sz > 0 && sz <= struct_size {
                            candidates.push((0, 3, sz, "__vftable".to_string(), vft_ty));
                        }
                    }
                }
                TypeData::BaseClass(bc) => {
                    let Ok(off) = int4::try_from(bc.offset) else { continue };
                    let Some(base_ty) = self.resolve_type(bc.base_class) else { continue };
                    let sz = base_ty.get_size();
                    if sz <= 0 || off < 0 || off.saturating_add(sz) > struct_size {
                        continue;
                    }
                    let bname = base_field_name(base_ty.get_name(), off);
                    let prio = if base_ty.num_depend() == 0 && sz == 1 { 4 } else { 1 };
                    candidates.push((off, prio, sz, bname, base_ty));
                }
                TypeData::VirtualBaseClass(vb) => {
                    let Ok(off) = int4::try_from(vb.base_pointer_offset) else { continue };
                    if !seen_vbptr_offsets.insert(off) {
                        continue;
                    }
                    let ptr_ty = self
                        .resolve_type(vb.base_pointer)
                        .or_else(|| self.void_ptr_type());
                    let Some(ptr_ty) = ptr_ty else { continue };
                    let sz = ptr_ty.get_size();
                    if sz <= 0 || off < 0 || off.saturating_add(sz) > struct_size {
                        continue;
                    }
                    let name = if off == 0 {
                        "__vbptr".to_string()
                    } else {
                        format!("__vbptr_{off:x}")
                    };
                    candidates.push((off, 2, sz, name, ptr_ty));
                }
                TypeData::Member(m) => {
                    let mname = m.name.to_string();
                    if mname.is_empty() {
                        continue;
                    }
                    if let Some(bf) = self.lookup_bitfield(m.field_type) {
                        let Some(ty) = self.resolve_type(bf.underlying_type) else { continue };
                        let num_bits = int4::from(bf.length);
                        if num_bits <= 0 || num_bits > 64 {
                            continue;
                        }
                        let Ok(byte_off) = i64::try_from(m.offset) else { continue };
                        let Some(start) = byte_off.checked_mul(8).and_then(|b| b.checked_add(i64::from(bf.position))) else {
                            continue;
                        };
                        if start >= 0 && start + i64::from(num_bits) <= end_bit {
                            raw_bits.push((start, num_bits, mname.into_owned(), ty));
                        }
                        continue;
                    }
                    let Ok(off) = int4::try_from(m.offset) else { continue };
                    let Some(ty) = self.resolve_type(m.field_type) else { continue };
                    let sz = ty.get_size();
                    if ty.get_metatype() == type_metatype::TYPE_VOID
                        || sz <= 0
                        || off < 0
                        || off.saturating_add(sz) > struct_size
                    {
                        continue;
                    }
                    candidates.push((off, 0, sz, mname.into_owned(), ty));
                }
                _ => {}
            }
        }

        let mut true_bits: Vec<(i64, int4, String, Rc<Datatype>)> = Vec::new();
        for (start, num_bits, name, ty) in raw_bits {
            match byte_exact_bitfield(start, num_bits, self.types, &ty) {
                Some((off, plain)) => {
                    let sz = plain.get_size();
                    if off >= 0 && off.saturating_add(sz) <= struct_size {
                        candidates.push((off, 0, sz, name, plain));
                    }
                }
                None => true_bits.push((start, num_bits, name, ty)),
            }
        }

        // Sort by offset, then priority (Member < BaseClass < vbptr < vftable < empty base),
        // then wider field first so a full base class beats a smaller overlapping sentinel.
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(b.2.cmp(&a.2)));
        let mut fields: Vec<TypeField> = Vec::new();
        let mut cur_end: int4 = 0;
        for (off, _prio, sz, name, ty) in candidates {
            if off < cur_end {
                continue;
            }
            cur_end = off.saturating_add(sz);
            fields.push(TypeField::new(off, off, name, ty));
        }

        true_bits.sort_by_key(|b| b.0);
        let bits = group_bitfields(true_bits, self.types.is_big_endian());
        (fields, bits)
    }

    fn lookup_bitfield(&self, ti: TypeIndex) -> Option<BitfieldType> {
        let item = self.finder.find(ti).ok()?;
        match item.parse().ok()? {
            TypeData::Bitfield(bf) => Some(bf),
            _ => None,
        }
    }

    fn collect_field_list(&self, start: TypeIndex) -> Vec<TypeData<'a>> {
        let mut out = Vec::new();
        let mut seen: HashSet<TypeIndex> = HashSet::new();
        let mut next = Some(start);
        for _ in 0..MAX_FIELDLIST_CONTINUATIONS {
            let Some(ti) = next.take() else { break };
            if !seen.insert(ti) {
                break;
            }
            let Ok(item) = self.finder.find(ti) else { break };
            let Ok(TypeData::FieldList(fl)) = item.parse() else { break };
            out.extend(fl.fields);
            next = fl.continuation;
        }
        out
    }

    fn void_ptr_type(&self) -> Option<Rc<Datatype>> {
        let v = self.types.get_type_void().ok()?;
        self.types.get_type_pointer(self.ptr_size, v, self.word_size).ok()
    }

    fn vftable_ptr_type(&self) -> Option<Rc<Datatype>> {
        let vp = self.void_ptr_type()?;
        self.types.get_type_pointer(self.ptr_size, vp, self.word_size).ok()
    }

    fn build_procedure_proto(
        &mut self,
        func_name: &str,
        p: &ProcedureType,
        param_names: &[String],
        is_32bit_x86: bool,
    ) -> Option<(PrototypePieces, Option<&'static str>)> {
        let outtype = match p.return_type {
            Some(ti) => self.resolve_type(ti).or_else(|| self.types.get_type_void().ok())?,
            None => self.types.get_type_void().ok()?,
        };
        let (intypes, first_var_arg_slot) = self.resolve_arg_list(p.argument_list)?;
        let innames: Vec<String> = (0..intypes.len())
            .map(|i| param_names.get(i).cloned().unwrap_or_default())
            .collect();
        let model = calling_convention_model(p.attributes.calling_convention(), false, is_32bit_x86);
        Some((
            PrototypePieces {
                name: func_name.to_string(),
                outtype: Some(outtype),
                intypes,
                innames,
                first_var_arg_slot,
                output_storage: None,
                input_storage: Vec::new(),
                kuna_library_names: None,
            },
            model,
        ))
    }

    fn build_member_fn_proto(
        &mut self,
        func_name: &str,
        m: &MemberFunctionType,
        param_names: &[String],
        is_32bit_x86: bool,
    ) -> Option<(PrototypePieces, Option<&'static str>)> {
        let outtype = self
            .resolve_type(m.return_type)
            .or_else(|| self.types.get_type_void().ok())?;
        let (args, arg_vararg) = self.resolve_arg_list(m.argument_list)?;

        let mut intypes = Vec::with_capacity(args.len() + 1);
        let mut innames = Vec::with_capacity(args.len() + 1);
        let has_this = m.this_pointer_type.is_some();
        let name_offset: usize;
        let first_var_arg_slot: i32;

        if let Some(this_ti) = m.this_pointer_type {
            let this_ty = self.resolve_type(this_ti).or_else(|| {
                let cls = self.resolve_type(m.class_type)?;
                self.types.get_type_pointer(self.ptr_size, cls, self.word_size).ok()
            })?;
            intypes.push(this_ty);
            innames.push("this".to_string());
            name_offset = usize::from(param_names.first().map(String::as_str) == Some("this"));
            first_var_arg_slot = if arg_vararg >= 0 { arg_vararg + 1 } else { -1 };
        } else {
            name_offset = 0;
            first_var_arg_slot = arg_vararg;
        }

        for (i, ty) in args.into_iter().enumerate() {
            intypes.push(ty);
            innames.push(param_names.get(i + name_offset).cloned().unwrap_or_default());
        }

        let model = calling_convention_model(m.attributes.calling_convention(), has_this, is_32bit_x86);
        Some((
            PrototypePieces {
                name: func_name.to_string(),
                outtype: Some(outtype),
                intypes,
                innames,
                first_var_arg_slot,
                output_storage: None,
                input_storage: Vec::new(),
                kuna_library_names: None,
            },
            model,
        ))
    }

    fn resolve_arg_list(&mut self, arglist_ti: TypeIndex) -> Option<(Vec<Rc<Datatype>>, i32)> {
        if arglist_ti == TypeIndex(0) {
            return Some((Vec::new(), -1));
        }
        let item = self.finder.find(arglist_ti).ok()?;
        let TypeData::ArgumentList(al) = item.parse().ok()? else {
            return None;
        };
        let mut out = Vec::with_capacity(al.arguments.len());
        let mut first_var_arg_slot: i32 = -1;
        for (i, &arg_ti) in al.arguments.iter().enumerate() {
            if self.is_notype(arg_ti) {
                first_var_arg_slot = out.len() as i32;
                break;
            }
            let ty = self.resolve_type(arg_ti)?;
            if ty.get_metatype() == type_metatype::TYPE_VOID {
                if al.arguments.len() == 1 && i == 0 {
                    break;
                }
                return None;
            }
            out.push(ty);
        }
        Some((out, first_var_arg_slot))
    }

    fn is_notype(&self, ti: TypeIndex) -> bool {
        if ti == TypeIndex(0) {
            return true;
        }
        matches!(
            self.finder.find(ti).ok().and_then(|t| t.parse().ok()),
            Some(TypeData::Primitive(PrimitiveType { kind: PrimitiveKind::NoType, indirection: None }))
        )
    }
}

/// Map CodeView `CV_call_e` + `has_this` to a kuna Windows cspec prototype model name.
pub(crate) fn calling_convention_model(
    cv_call: u8,
    has_this: bool,
    is_32bit_x86: bool,
) -> Option<&'static str> {
    if is_32bit_x86 {
        match cv_call {
            0x00 | 0x01 => Some("__cdecl"),
            0x04 | 0x05 => Some("__fastcall"),
            0x07 | 0x08 => Some("__stdcall"),
            0x0b => Some("__thiscall"),
            _ => None,
        }
    } else if has_this {
        // `x86-64-win.cspec` registers `__thiscall` with `thisbeforeretpointer="true"`.
        Some("__thiscall")
    } else {
        None
    }
}

fn record_def(
    by_unique: &mut HashMap<String, (TypeIndex, bool)>,
    by_name: &mut HashMap<(u8, String), (TypeIndex, bool)>,
    tag: u8,
    name: String,
    unique: Option<String>,
    idx: TypeIndex,
    rich: bool,
) {
    if let Some(u) = unique {
        if !u.is_empty() {
            by_unique
                .entry(u)
                .and_modify(|cur| {
                    if rich && !cur.1 {
                        *cur = (idx, rich);
                    }
                })
                .or_insert((idx, rich));
        }
    }
    if !name.is_empty() {
        by_name
            .entry((tag, name))
            .and_modify(|cur| {
                if rich && !cur.1 {
                    *cur = (idx, rich);
                }
            })
            .or_insert((idx, rich));
    }
}

fn aggregate_size(size: u64) -> Option<int4> {
    if size == 0 || size > int4::MAX as u64 {
        None
    } else {
        Some(size as int4)
    }
}

fn is_anonymous_tag(name: &str) -> bool {
    name.is_empty()
        || name == "<unnamed-tag>"
        || name == "<anonymous-tag>"
        || name == "__unnamed"
        || name.ends_with("::<unnamed-tag>")
        || name.ends_with("::<anonymous-tag>")
}

fn clean_type_name(raw: &str, idx: TypeIndex, fallback: &str) -> String {
    if is_anonymous_tag(raw) {
        return format!("{fallback}_{:x}", idx.0);
    }
    raw.to_string()
}

fn base_field_name(base_type_name: &str, offset: int4) -> String {
    let short = base_type_name.rsplit("::").next().unwrap_or(base_type_name);
    let clean: String = short
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    let trimmed = clean.trim_matches('_');
    if trimmed.is_empty() {
        format!("base_{offset:x}")
    } else if offset == 0 {
        format!("base_{trimmed}")
    } else {
        format!("base_{trimmed}_{offset:x}")
    }
}

fn resolve_record_name(
    types: &dyn TypeFactory,
    base: &str,
    size: Option<int4>,
    want: type_metatype,
) -> Option<String> {
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let name = match (attempt, size) {
            (0, _) => base.to_string(),
            (_, None) => return None,
            (1, Some(s)) => format!("{base}_{s}"),
            (n, Some(s)) => format!("{base}_{s}_{n}"),
        };
        match types.find_by_name(&name) {
            Ok(None) => return Some(name),
            Ok(Some(t)) => {
                if t.get_metatype() != want {
                    continue;
                }
                if t.is_incomplete() {
                    return Some(name);
                }
                match size {
                    Some(s) if t.get_size() != s => continue,
                    _ => return Some(name),
                }
            }
            Err(_) => return None,
        }
    }
    None
}

fn derived_alignment(size: int4, fields: &[TypeField], bits: &[TypeBitField]) -> int4 {
    let derived = fields
        .iter()
        .map(|f| f.field_type.get_alignment())
        .chain(bits.iter().map(|b| b.field_type.get_alignment()))
        .max()
        .unwrap_or(1)
        .max(1);
    let mut a = 1;
    while a * 2 <= derived && a * 2 <= size {
        a *= 2;
    }
    a
}

fn variant_to_u64(v: Variant) -> u64 {
    match v {
        Variant::U8(x) => u64::from(x),
        Variant::U16(x) => u64::from(x),
        Variant::U32(x) => u64::from(x),
        Variant::U64(x) => x,
        Variant::I8(x) => i64::from(x) as u64,
        Variant::I16(x) => i64::from(x) as u64,
        Variant::I32(x) => i64::from(x) as u64,
        Variant::I64(x) => x as u64,
    }
}
