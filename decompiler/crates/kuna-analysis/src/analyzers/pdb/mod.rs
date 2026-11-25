//! `pdb` — the PE PDB (Program Database) metadata tier.
//!
//! Recovers function names (global + static `S_LPROC32`), TPI aggregate/enum/
//! bitfield/pointer/array/function types, typed prototypes (with `this` and
//! `CV_call_e` calling conventions), `noreturn` flags, typed globals
//! (`S_GDATA32`/`S_LDATA32`), stack locals (`S_BPREL32`, `S_REGREL32`,
//! `S_LOCAL` + `S_DEFRANGE_*` + `S_FRAMEPROC`), and `S_INLINESITE` call sites.

pub mod codeview;
pub mod kuna_pdbinterior;
pub mod locate;
pub mod types;
pub mod walk;

use object::read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64};
use object::{FileKind, Object};
use pdb::FallibleIterator;

use kuna_decomp::dtype::type_metatype;

use crate::pass::{
    AnalysisCtx, AnalysisOutput, AnalysisPass, FidMatch, LocalFact, NoReturnFact, Phase, SymFact,
    SymKind, TypedDataFact,
};

/// The PE PDB-consuming pass (gate id `pdb`, default-on).
#[derive(Default)]
pub struct PdbPass;

impl AnalysisPass for PdbPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "pdb"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();

        if ctx.file.format() != object::BinaryFormat::Pe {
            return out;
        }
        let cv = codeview::extract_codeview(ctx.bytes);
        if cv.is_none() && !locate::ignore_guid() {
            return out;
        }
        let candidates = locate::pdb_candidates(ctx.image_path, cv.as_ref());
        if candidates.is_empty() {
            return out;
        }
        let Some(image_base) = pe_image_base(ctx.bytes) else {
            return out;
        };
        let Some(mut pdb) = open_fingerprint_matched(&candidates, cv.as_ref()) else {
            return out;
        };

        let tpi = pdb.type_information().ok();
        let ipi = pdb.id_information().ok();
        let id_finder = ipi.as_ref().map(|info| {
            let mut finder = info.finder();
            let mut iter = info.iter();
            while let Ok(Some(_)) = iter.next() {
                finder.update(&iter);
            }
            finder
        });
        let word_size = ctx
            .arch
            .manage()
            .get_default_code_space()
            .map(|s| s.get_word_size())
            .unwrap_or(1);
        let mut type_builder = tpi
            .as_ref()
            .map(|info| types::PdbTypeBuilder::new(info, ctx.arch.types(), word_size));

        let arch = ctx.file.architecture();
        let is_32bit_x86 = arch == object::Architecture::I386;
        let walked = walk::walk_all(
            &mut pdb,
            image_base,
            arch,
            id_finder.as_ref(),
            type_builder.as_ref(),
        );

        for f in walked.functions {
            if f.name.is_empty() {
                continue;
            }
            out.symbols.push(SymFact {
                addr: f.vma,
                name: f.name.clone(),
                kind: SymKind::Function,
            });
            out.fid_names.push(FidMatch {
                addr: f.vma,
                name: f.name.clone(),
                by_signature: false,
            });
            if f.noreturn {
                out.noreturn.push(NoReturnFact { addr: f.vma, name: f.name.clone() });
            }
            if let (Some(ti), Some(tb)) = (f.type_index, type_builder.as_mut()) {
                if let Some((pieces, model)) =
                    tb.build_prototype(&f.name, ti, &f.param_names, is_32bit_x86)
                {
                    out.pdb_prototypes.push((f.vma, pieces, model));
                }
            }
        }

        if let Some(tb) = type_builder.as_mut() {
            for g in walked.globals {
                let Some(ty) = tb.resolve_type(g.type_index) else {
                    continue;
                };
                if ty.get_metatype() == type_metatype::TYPE_VOID || ty.get_size() <= 0 {
                    continue;
                }
                out.typed_data.push(TypedDataFact { addr: g.vma, name: g.name, type_: ty });
            }
            for l in walked.locals {
                let Some(ty) = tb.resolve_type(l.type_index) else {
                    continue;
                };
                if ty.get_metatype() == type_metatype::TYPE_VOID || ty.get_size() <= 0 {
                    continue;
                }
                out.locals.push(LocalFact {
                    func_addr: l.func_addr,
                    name: l.name,
                    type_: ty,
                    stack_offset: l.stack_offset,
                });
            }
        }

        out.inline_sites = walked.inline_sites;
        out
    }
}

/// Open the first candidate `.pdb` whose `{guid, age}` matches `cv`, or accept
/// a mismatch/absent CodeView record when [`locate::ignore_guid`] is enabled.
pub(crate) fn open_fingerprint_matched(
    candidates: &[std::path::PathBuf],
    cv: Option<&codeview::CodeViewInfo>,
) -> Option<pdb::PDB<'static, std::fs::File>> {
    let ignore = locate::ignore_guid();
    if cv.is_none() && !ignore {
        return None;
    }
    for path in candidates {
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        let Ok(mut pdb) = pdb::PDB::open(file) else {
            continue;
        };
        let Ok(info) = pdb.pdb_information() else {
            continue;
        };
        let guid = info.guid.to_string();
        match cv {
            Some(cv) if locate::fingerprint_ok(cv, &guid, info.age) => return Some(pdb),
            Some(cv) if ignore => {
                kuna_base::notes::say_once(
                    &format!("pdb-ignore:{}", path.display()),
                    &format!(
                        "[kuna pdb] {}: age {} guid {} does not match the image's CodeView record \
                         (age {} guid {}); applied because --pdb-ignore-guid is set",
                        path.display(),
                        info.age,
                        guid.to_uppercase(),
                        cv.age(),
                        cv.guid_string().unwrap_or_else(|| "<none, NB10 record>".to_string()),
                    ),
                );
                return Some(pdb);
            }
            Some(cv) => {
                kuna_base::notes::say_once(
                    &path.display().to_string(),
                    &format!(
                        "[kuna pdb] {}: age {} guid {} does not match the image's CodeView record \
                         (age {} guid {}); not applied",
                        path.display(),
                        info.age,
                        guid.to_uppercase(),
                        cv.age(),
                        cv.guid_string().unwrap_or_else(|| "<none, NB10 record>".to_string()),
                    ),
                );
            }
            None => {
                kuna_base::notes::say_once(
                    &format!("pdb-ignore-nocv:{}", path.display()),
                    &format!(
                        "[kuna pdb] {}: image has no CodeView record; applied because --pdb-ignore-guid is set",
                        path.display(),
                    ),
                );
                return Some(pdb);
            }
        }
    }
    None
}

/// Read the PE `ImageBase` (the RVA→VMA addend) from the optional header.
pub(crate) fn pe_image_base(bytes: &[u8]) -> Option<u64> {
    match FileKind::parse(bytes).ok()? {
        FileKind::Pe64 => Some(image_base_of(&PeFile64::parse(bytes).ok()?)),
        FileKind::Pe32 => Some(image_base_of(&PeFile32::parse(bytes).ok()?)),
        _ => None,
    }
}

fn image_base_of<Pe: ImageNtHeaders>(pe: &PeFile<Pe>) -> u64 {
    pe.relative_address_base()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_identity() {
        let p = PdbPass;
        assert_eq!(p.id(), "pdb");
        assert_eq!(p.phase(), Phase::P1);
    }

    #[test]
    fn pe_image_base_reads_pdb_min() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pdb_min.exe");
        let bytes = std::fs::read(path).expect("read pdb_min.exe fixture");
        let base = pe_image_base(&bytes).expect("pdb_min.exe is a PE with an image base");
        assert_ne!(base, 0, "a PE image base is nonzero");
        assert_eq!(base & 0xfff, 0, "the image base is page-aligned");
    }

    #[test]
    fn pe_image_base_non_pe_is_none() {
        assert_eq!(pe_image_base(b"\x7fELF not a PE"), None);
    }
}
