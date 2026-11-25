//! Serialize a document with the ASCII escaping used by Kuna's JSON interface.

use super::UnicodeEscape;
use serde::Serialize;
use serde_json::ser::{Formatter, PrettyFormatter};
use std::io::{self, BufWriter, Write};

pub(crate) fn write_ascii_document(out: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
    let mut out = BufWriter::with_capacity(1 << 16, out);
    let formatter = AsciiPretty(PrettyFormatter::new());
    value.serialize(&mut serde_json::Serializer::with_formatter(&mut out, formatter))
        .map_err(io::Error::from)?;
    out.write_all(b"\n")?;
    out.flush()
}

struct AsciiPretty(PrettyFormatter<'static>);

impl Formatter for AsciiPretty {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (offset, ch) in fragment.char_indices() {
            if ch < '\u{7f}' {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..offset])?;
            write!(writer, "{}", UnicodeEscape(ch))?;
            start = offset + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn begin_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_array(writer)
    }

    fn end_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object(writer)
    }

    fn end_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_object_key(writer, first)
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object_value(writer)
    }
}
