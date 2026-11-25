//! Compiler-attributed inline sites keyed by the enclosing caller address.

/// Identity in the debug information for this image. Separate namespaces keep
/// PDB IPI indices and DWARF section offsets distinct on mixed-debug inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InlineeId {
    Pdb(u32),
    Dwarf(u64),
}

/// One inlined callee instance inside a caller function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedInlineSite {
    /// Identity of the inlinee in its source debug information.
    pub inlinee_id: InlineeId,
    /// Normalized display name of the inlined function or method.
    pub inlinee_name: String,
    /// Inline nesting depth inside the caller (`0` for top-level inline sites).
    pub depth: u16,
    /// Sorted, non-overlapping `[start_vma, end_vma)` instruction byte ranges
    /// covered by this inline site inside the caller.
    pub ranges: Vec<(u64, u64)>,
}
