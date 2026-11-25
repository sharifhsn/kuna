//! Serialize borrowed inventory records without building a second function list.
//! JSON layout belongs to serde_json; the formatter adds ASCII-safe strings.

use std::collections::BTreeMap;
use std::io::{self, Write};

use kuna_console::engine::FunctionEntry;
use kuna_decomp::kuna_inlinesites::{InlineeId, ParkedInlineSite};
use serde::ser::Error as _;
use serde::{Serialize, Serializer};

use crate::funcdecl::Declared;
use crate::jsonfmt::{write_ascii_document, Json};

#[allow(clippy::too_many_arguments)]
pub(super) fn write(
    out: &mut dyn Write,
    binary: &str,
    entries: &[FunctionEntry],
    total: usize,
    error: Option<&str>,
    limits: Option<&Json>,
    display_address: &dyn Fn(u64) -> u64,
    declared: &Declared,
    inline_sites: &BTreeMap<u64, Vec<ParkedInlineSite>>,
) -> io::Result<()> {
    let fid_databases = declared.fid_databases_field().map(|(_, value)| value);
    let document = Document {
        binary,
        count: entries.len(),
        total,
        error,
        notes: declared.notes(),
        fid_databases: fid_databases.as_ref().map(JsonView),
        functions: Entries {
            entries,
            display_address,
            declared,
            inline_sites,
        },
        limits: limits.map(JsonView),
    };
    write_ascii_document(out, &document)
}

#[derive(Serialize)]
struct Document<'a> {
    binary: &'a str,
    count: usize,
    total: usize,
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    notes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    fid_databases: Option<JsonView<'a>>,
    functions: Entries<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<JsonView<'a>>,
}

struct Entries<'a> {
    entries: &'a [FunctionEntry],
    display_address: &'a dyn Fn(u64) -> u64,
    declared: &'a Declared,
    inline_sites: &'a BTreeMap<u64, Vec<ParkedInlineSite>>,
}

impl Serialize for Entries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.entries.iter().map(|entry| {
            let address = (self.display_address)(entry.addr.get_offset());
            Entry {
                name: &entry.name,
                address,
                address_hex: format!("0x{address:x}"),
                aliases: &entry.aliases,
                object_location: entry.object_location.as_ref().map(|location| Location {
                    section_index: location.section_index,
                    section: &location.section,
                    offset: location.offset,
                    offset_hex: format!("0x{:x}", location.offset),
                }),
                size: entry.size,
                inline_sites: self.inline_sites.get(&entry.addr.get_offset())
                    .map(|sites| sites.iter().map(InlineSite::from).collect()),
                declared: self
                    .declared
                    .bytes_label(entry.addr.get_offset())
                    .map(|bytes| Marker { bytes }),
            }
        }))
    }
}

#[derive(Serialize)]
struct Entry<'a> {
    name: &'a str,
    address: u64,
    address_hex: String,
    aliases: &'a [String],
    object_location: Option<Location<'a>>,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    declared: Option<Marker<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inline_sites: Option<Vec<InlineSite<'a>>>,
}

#[derive(Serialize)]
struct InlineSite<'a> {
    source: &'static str,
    id: String,
    name: &'a str,
    depth: u16,
    ranges: Vec<[String; 2]>,
}

impl<'a> From<&'a ParkedInlineSite> for InlineSite<'a> {
    fn from(site: &'a ParkedInlineSite) -> Self {
        let (source, id) = match site.inlinee_id {
            InlineeId::Pdb(id) => ("pdb", u64::from(id)),
            InlineeId::Dwarf(id) => ("dwarf", id),
        };
        Self {
            source,
            id: format!("0x{id:x}"),
            name: &site.inlinee_name,
            depth: site.depth,
            ranges: site.ranges.iter().map(|(start, end)| {
                [format!("0x{start:x}"), format!("0x{end:x}")]
            }).collect(),
        }
    }
}

#[derive(Serialize)]
struct Location<'a> {
    section_index: usize,
    section: &'a str,
    offset: u64,
    offset_hex: String,
}

#[derive(Serialize)]
struct Marker<'a> {
    bytes: &'a str,
}

struct JsonView<'a>(&'a Json);

impl Serialize for JsonView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Json::Null => serializer.serialize_none(),
            Json::Bool(value) => serializer.serialize_bool(*value),
            Json::Str(value) => serializer.serialize_str(value),
            Json::Number(value) => {
                let raw = serde_json::value::RawValue::from_string(value.clone())
                    .map_err(S::Error::custom)?;
                raw.serialize(serializer)
            }
            Json::Array(values) => serializer.collect_seq(values.iter().map(JsonView)),
            Json::Object(fields) => {
                serializer.collect_map(fields.iter().map(|(key, value)| (key, JsonView(value))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_base::address::{AddrSpacePtr, Address};
    use kuna_console::engine::{EntryProvenance, ObjectLocation};

    #[test]
    fn records_and_optional_limits_match_legacy_bytes() {
        let entries = [
            FunctionEntry {
                name: "函数🚀\x7f\n\"\\".into(),
                addr: Address::from_space_ptr(AddrSpacePtr::Null, 0),
                aliases: vec!["é\t".into(), "别名".into()],
                size: u64::MAX,
                object_location: Some(ObjectLocation {
                    section_index: 7,
                    section: "__text\u{2028}".into(),
                    offset: u64::MAX,
                }),
                provenance: EntryProvenance::Mapped,
                binding: None,
            },
            FunctionEntry {
                name: String::new(),
                addr: Address::from_space_ptr(AddrSpacePtr::Null, u64::MAX),
                aliases: vec![],
                size: 0,
                object_location: None,
                provenance: EntryProvenance::Mapped,
                binding: None,
            },
        ];
        let limits = Json::Object(vec![
            (
                "maxinstruction".into(),
                Json::Number("18446744073709551615".into()),
            ),
            ("jumptablemax".into(), Json::Number("0".into())),
            (
                "over".into(),
                Json::Array(vec![Json::Object(vec![
                    ("name".into(), Json::Str("é".into())),
                    ("over_maxinstruction".into(), Json::Bool(true)),
                    ("switches_over_jumptablemax".into(), Json::Array(vec![])),
                ])]),
            ),
        ]);
        for entries in [&entries[..0], &entries[..1], &entries[..]] {
            for error in [None, Some("失败\0\x1f")] {
                for limits in [None, Some(&limits)] {
                    let display_address = |address| address ^ 0x1234;
                    let declared = Declared::default();
                    let mut bytes = Vec::new();
                    write(
                        &mut bytes,
                        "输入🚀",
                        entries,
                        123,
                        error,
                        limits,
                        &display_address,
                        &declared,
                        &BTreeMap::new(),
                    )
                    .unwrap();
                    let expected = super::super::functions_json(
                        "输入🚀",
                        entries,
                        123,
                        error,
                        limits,
                        &display_address,
                        &declared,
                    );
                    assert_eq!(bytes, expected.as_bytes());
                }
            }
        }
    }

    #[test]
    fn every_unicode_scalar_has_the_legacy_escape_spelling() {
        let text: String = (0..=0x10ffff).filter_map(char::from_u32).collect();
        let mut bytes = Vec::new();
        write_ascii_document(&mut bytes, &text).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        assert_eq!(
            bytes,
            crate::jsonfmt::dumps_indent2(&Json::Str(text)).as_bytes()
        );
    }

    #[test]
    fn write_errors_preserve_their_kind_and_run_verdict() {
        struct FailingWriter(io::ErrorKind);

        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "output failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::PermissionDenied] {
            for run_error in [None, Some("no functions discovered")] {
                let result = write(
                    &mut FailingWriter(kind),
                    "fixture",
                    &[],
                    0,
                    run_error,
                    None,
                    &|address| address,
                    &Declared::default(),
                    &BTreeMap::new(),
                );
                assert_eq!(result.as_ref().unwrap_err().kind(), kind);
                let status = super::super::finish_with_run_error(result, run_error);
                let expected = if kind == io::ErrorKind::BrokenPipe {
                    i32::from(run_error.is_some())
                } else {
                    1
                };
                assert_eq!(status, expected);
            }
        }
    }
}
