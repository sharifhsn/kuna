//! (kuna `pdb`) Parked inline-site records (`S_INLINESITE`/`S_INLINESITE2`) keyed
//! by enclosing caller function VMA on [`crate::architecture::Architecture`].

/// One inlined callee instance inside a caller function, recovered from PDB
/// `S_INLINESITE`/`S_INLINESITE2` + `ModuleInfo::inlinees()` + IPI `IdFinder`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedInlineSite {
    /// Raw IPI `IdIndex` of the inlinee (stable identity across callers).
    pub inlinee_id: u32,
    /// Normalized display name of the inlined function or method.
    pub inlinee_name: String,
    /// Inline nesting depth inside the caller (`0` for top-level inline sites).
    pub depth: u16,
    /// Sorted, non-overlapping `[start_vma, end_vma)` instruction byte ranges
    /// covered by this inline site inside the caller.
    pub ranges: Vec<(u64, u64)>,
}
