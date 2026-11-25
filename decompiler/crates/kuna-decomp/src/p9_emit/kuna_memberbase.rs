//! Member addresses must use a pointer compatible with the emitted variable.

use std::rc::Rc;

use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;

fn same_type(left: &Rc<Datatype>, right: &Rc<Datatype>) -> bool {
    Rc::ptr_eq(left, right) || matches!(left.compare(right, 10), Ok(0))
}

pub(crate) fn needs_cast(
    fd: &Funcdata,
    base: VarnodeId,
    pointer: &Rc<Datatype>,
) -> bool {
    if !fd.get_arch().stack_views
        || !fd.get_func_proto().has_store()
        || pointer.is_formal_pointer_rel()
    {
        return false;
    }
    let Some(declared) = crate::printc::declared_variable_type(fd, base) else {
        return false;
    };
    declared.get_size() == pointer.get_size()
        && matches!(
            declared.get_metatype(),
            type_metatype::TYPE_INT
                | type_metatype::TYPE_UINT
                | type_metatype::TYPE_UNKNOWN
                | type_metatype::TYPE_PTR
        )
        && !same_type(&declared, pointer)
}

/// A field address stored in a reused record-pointer local needs the local's
/// declared pointer type. The intermediate IR cast can describe the slot
/// (`T **`) while the C identifier is declared as the record pointer (`T *`).
pub(super) fn assigned_slot_type(
    fd: &Funcdata,
    op: OpId,
    nominal: &Rc<Datatype>,
    declared: &Rc<Datatype>,
) -> Option<Rc<Datatype>> {
    if declared.get_metatype() != type_metatype::TYPE_PTR
        || nominal.is_formal_pointer_rel()
        || declared.is_pointer_rel()
        || nominal.get_size() != declared.get_size()
        || nominal.get_word_size() != declared.get_word_size()
        || nominal.get_pointer_space().map(|s| s.get_index())
            != declared.get_pointer_space().map(|s| s.get_index())
    {
        return None;
    }
    let slot = nominal.get_ptr_to()?;
    if !same_type(&slot, declared) {
        return None;
    }
    let operation = fd.obank().get(op)?;
    if operation.code() != OpCode::CPUI_CAST {
        return None;
    }
    let field_op = fd.vbank().get(operation.get_in(0)?)?.get_def()?;
    let field = fd.obank().get(field_op)?;
    if field.code() != OpCode::CPUI_PTRSUB {
        return None;
    }
    let base = fd.vn_type_read_facing(field.get_in(0)?, field_op);
    let record = declared.get_ptr_to()?;
    let aggregate = base.get_ptr_to()?;
    if base.is_formal_pointer_rel()
        || record.get_metatype() != type_metatype::TYPE_STRUCT
        || !same_type(&record, &aggregate)
    {
        return None;
    }
    let offset = fd.vbank().get(field.get_in(1)?)?;
    let bytes = offset
        .get_offset()
        .checked_mul(u64::from(base.get_word_size()?))?;
    if !offset.is_constant() || !bytes.is_multiple_of(record.get_alignment().max(1) as u64) {
        return None;
    }
    let (member, residual) = record.get_sub_type(i64::try_from(bytes).ok()?).ok()?;
    let member = member?;
    (residual == 0 && same_type(&member, declared))
        .then(|| Rc::clone(declared))
}
