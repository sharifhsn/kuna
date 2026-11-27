//! `kuna twins` — report function bodies that are byte-identical once the
//! address-bearing bytes are masked, without excising anything.
//!
//! ```text
//!   kuna twins <binary> --define-function @bounds.txt [--min-bytes N] [--json]
//! ```
//!
//! # Why this exists
//!
//! `[PROPOSAL] outlining` (kuna #6, kuna #10) wants repeated inline expansions
//! collapsed into one synthesised helper. Two smaller steps come first, and both
//! can be answered from bytes alone:
//!
//! 1. **Twin detection** — which bodies repeat, and how far they agree.
//! 2. **A report** — the pairs, so a human or agent can name a region before any
//!    body is excised.
//!
//! This command is step 2. It changes no emitted C, writes no file, and
//! synthesises no helper; it is a query over the image the caller already has.
//! Manual outlining (`#10`) needs a head/exit pair per site by hand, and the
//! report is what removes the hand part.
//!
//! # The comparison
//!
//! Bodies come from `--define-function` extents, never from discovery: the
//! boundaries are the caller's, so a twin cannot be manufactured by two
//! functions being clipped into the same range. Each body is then **masked** —
//! `E8`/`E9` and `0F 8x` rel32 operands, `FF /2` and `FF /4` RIP-relative
//! disp32, and any 4-byte little-endian value that lands inside an executable
//! range are blanked — and bodies are grouped by the masked result.
//!
//! Masking addresses rather than normalising registers is deliberate. Outlined
//! copies of one region do not rename registers relative to each other (the
//! compiler's allocator may, but the sequences that survive outlining are the
//! ones it emitted identically); blanking registers too would merge unrelated
//! arithmetic of the same shape, which is exactly the false positive that makes
//! twin reporting unusable on a large image.
//!
//! Group order and row order are both by address, so two runs over one image are
//! byte-identical.

use std::collections::BTreeMap;

use kuna_analysis::loadimage_object::ObjectLoadImage;

use crate::args::take_value as take;
use crate::jsonfmt::Json;

/// Groups below this many bytes are noise from short common sequences.
const DEFAULT_MIN_BYTES: usize = 24;

struct Args {
    binary: String,
    decls: Vec<crate::funcdecl::FuncDecl>,
    min_bytes: usize,
    json: bool,
}

pub fn run(argv: &[String]) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            usage();
            return 2;
        }
    };
    match report(&args) {
        Ok(text) => crate::output::emit_with_status(&text, 0),
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn usage() {
    eprintln!(
        "usage: kuna twins <binary> --define-function <start-end | @file>.. [--min-bytes N] [--json]\n\
         \n\
         Groups function bodies by their bytes with address operands masked; reports\n\
         two or more sites per group and excises nothing (the outlining report).\n\
         Bodies come from --define-function extents only: --define-function @bounds.txt\n\
         with the same file the decompile uses, never from discovery.\n\
         --json is {{groups, rows}}: rows carry addr, size, masked_bytes and sites, and\n\
         `groups` is the group count. The tab form is one row per site under an\n\
         `# addr\tsize\tmasked_bytes\tsites` header."
    );
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut binary: Option<String> = None;
    let mut decls = Vec::new();
    let mut min_bytes = DEFAULT_MIN_BYTES;
    let mut json = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--define-function" | "--functions" => {
                let value = take(argv, &mut i, "--define-function")?;
                decls.extend(crate::funcdecl::parse_flag(&value)?);
                i += 1;
            }
            "--min-bytes" => {
                let value = take(argv, &mut i, "--min-bytes")?;
                min_bytes = value
                    .strip_prefix("0x")
                    .map(|v| usize::from_str_radix(v, 16))
                    .unwrap_or_else(|| value.parse())
                    .map_err(|_| format!("--min-bytes: {value} is not a number"))?;
                i += 1;
            }
            flag if flag.starts_with('-') => return Err(format!("unknown flag {flag}")),
            other => {
                if binary.replace(other.to_string()).is_some() {
                    return Err(format!("second binary {other}"));
                }
                i += 1;
            }
        }
    }
    let binary = binary.ok_or("no binary given")?;
    if decls.is_empty() {
        return Err("no --define-function extents: twins compares caller-declared bodies".into());
    }
    Ok(Args {
        binary,
        decls,
        min_bytes,
        json,
    })
}

fn report(args: &Args) -> Result<String, String> {
    let bytes = std::fs::read(&args.binary).map_err(|e| format!("{}: {e}", args.binary))?;
    let file = ObjectLoadImage::from_bytes_silent(&args.binary, &bytes)
        .map_err(|e| format!("could not parse {}: {e}", args.binary))?;
    let exec = file.executable_ranges();
    let bodies = bodies(&file, &bytes, &args.decls, &exec);
    let groups = group(bodies, args.min_bytes);
    Ok(render(&groups, args.json))
}

/// One caller-declared body, already masked.
struct Body {
    addr: u64,
    size: usize,
    key: Vec<u8>,
    /// Bytes the mask blanked; a copy with no address in it is the weak case.
    masked: usize,
}

fn bodies(
    file: &ObjectLoadImage,
    bytes: &[u8],
    decls: &[crate::funcdecl::FuncDecl],
    exec: &[(u64, u64)],
) -> Vec<Body> {
    let mut out = Vec::new();
    for decl in decls {
        let Some(end) = decl.end else { continue };
        if end <= decl.start {
            continue;
        }
        let Some(raw) = slice(file, bytes, decl.start, end) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let (key, masked) = mask(&raw, decl.start, exec);
        out.push(Body {
            addr: decl.start,
            size: raw.len(),
            key,
            masked,
        });
    }
    out.sort_by_key(|b| b.addr);
    out
}

/// The body's bytes, or `None` if any part has no file bytes.
fn slice(file: &ObjectLoadImage, bytes: &[u8], start: u64, end: u64) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((end - start) as usize);
    let mut at = start;
    while at < end {
        let section = file
            .section_metadata()
            .iter()
            .find(|s| at >= s.vma && at < s.vma + s.size)?;
        let offset = section.file_offset?;
        let avail = (section.vma + section.file_size?).min(end) - at;
        if avail == 0 {
            return None;
        }
        let from = usize::try_from(offset + (at - section.vma)).ok()?;
        out.extend_from_slice(bytes.get(from..from + avail as usize)?);
        at += avail;
    }
    Some(out)
}

/// Blank every byte that can differ between two copies of one region: branch
/// displacements, RIP-relative displacements, and any 4-byte value that lands
/// in executable memory. Blanked bytes become `0x00`.
fn mask(body: &[u8], base: u64, exec: &[(u64, u64)]) -> (Vec<u8>, usize) {
    let mut out = body.to_vec();
    let mut masked = 0usize;
    // Spans an operand form already owns; the absolute pass must not re-mask
    // inside them, or the opcode byte itself becomes part of the blank.
    let mut fixed = vec![false; body.len()];
    let mut blank = |out: &mut Vec<u8>, masked: &mut usize, from: usize, len: usize| {
        for byte in out.iter_mut().skip(from).take(len) {
            if *byte != 0 {
                *byte = 0;
                *masked += 1;
            }
        }
    };
    let mut i = 0usize;
    while i < body.len() {
        match body[i] {
            0xE8 | 0xE9 => {
                blank(&mut out, &mut masked, i + 1, 4);
                fixed[i..(i + 5).min(body.len())].fill(true);
                i += 5;
                continue;
            }
            0x0F if matches!(body.get(i + 1), Some(0x80..=0x8F)) => {
                blank(&mut out, &mut masked, i + 2, 4);
                fixed[i..(i + 6).min(body.len())].fill(true);
                i += 6;
                continue;
            }
            0xFF if body
                .get(i + 1)
                .is_some_and(|m| m & 0x38 == 0x10 || m & 0x38 == 0x20)
                && body
                    .get(i + 1)
                    .is_some_and(|m| m & 0xC7 == 0x05 || m & 0xC7 == 0x15) =>
            {
                // FF /2 or FF /4, mod=00 rm=101: RIP-relative disp32.
                blank(&mut out, &mut masked, i + 2, 4);
                fixed[i..(i + 6).min(body.len())].fill(true);
                i += 6;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    // Any absolute address the operand forms above did not cover.
    for at in 0..body.len().saturating_sub(3) {
        if fixed[at..at + 4].iter().any(|b| *b) {
            continue;
        }
        let value = u64::from(u32::from_le_bytes([
            body[at],
            body[at + 1],
            body[at + 2],
            body[at + 3],
        ]));
        let as_rva = value.wrapping_sub(base);
        if exec
            .iter()
            .any(|(lo, hi)| value >= *lo && value < *hi || as_rva >= *lo && as_rva < *hi)
        {
            blank(&mut out, &mut masked, at, 4);
        }
    }
    (out, masked)
}

struct Group {
    sites: Vec<(u64, usize, usize)>,
}

/// Group by masked bytes. A group is reported only when it has two sites.
fn group(bodies: Vec<Body>, min_bytes: usize) -> Vec<Group> {
    let mut by_key: BTreeMap<Vec<u8>, Vec<(u64, usize, usize)>> = BTreeMap::new();
    for body in bodies {
        if body.size < min_bytes {
            continue;
        }
        by_key
            .entry(body.key)
            .or_default()
            .push((body.addr, body.size, body.masked));
    }
    let mut groups: Vec<Group> = by_key
        .into_values()
        .filter(|sites| sites.len() > 1)
        .map(|sites| Group { sites })
        .collect();
    groups.sort_by_key(|g| g.sites[0].0);
    groups
}

fn render(groups: &[Group], json: bool) -> String {
    if json {
        let rows: Vec<Json> = groups
            .iter()
            .flat_map(|g| {
                g.sites.iter().map(move |(addr, size, masked)| {
                    Json::Object(vec![
                        ("addr".into(), Json::Str(format!("0x{addr:x}"))),
                        ("size".into(), Json::Number(size.to_string())),
                        ("masked_bytes".into(), Json::Number(masked.to_string())),
                        ("sites".into(), Json::Number(g.sites.len().to_string())),
                    ])
                })
            })
            .collect();
        let doc = Json::Object(vec![
            ("groups".into(), Json::Number(groups.len().to_string())),
            ("rows".into(), Json::Array(rows)),
        ]);
        return crate::jsonfmt::dumps_indent2(&doc);
    }
    let mut out = String::from("# addr\tsize\tmasked_bytes\tsites\n");
    for group in groups {
        for (addr, size, masked) in &group.sites {
            out.push_str(&format!(
                "{addr:#x}\t{size}\t{masked}\t{}\n",
                group.sites.len()
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(at: u64, bytes: &[u8]) -> Body {
        let (key, masked) = mask(bytes, at, &[(0x1000, 0x2000)]);
        Body {
            addr: at,
            size: bytes.len(),
            key,
            masked,
        }
    }

    #[test]
    fn address_operands_do_not_split_a_twin() {
        // call rel32 to two different places, same surrounding body.
        let a = [
            0x48, 0x8B, 0x01, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90,
        ];
        let b = [
            0x48, 0x8B, 0x01, 0xE8, 0x20, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90,
        ];
        let groups = group(vec![body(0x1000, &a), body(0x2000, &b)], 8);
        if groups.is_empty() {
            let x = body(0x1000, &a);
            let y = body(0x2000, &b);
            eprintln!(
                "A {:02x?}\nB {:02x?}\nsizes {} {}",
                x.key, y.key, x.size, y.size
            );
        }
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].sites.len(), 2);
    }

    #[test]
    fn differing_arithmetic_is_not_a_twin() {
        let a = [0x48, 0x01, 0xD8, 0x48, 0x01, 0xD8, 0xC3];
        let b = [0x48, 0x29, 0xD8, 0x48, 0x29, 0xD8, 0xC3];
        assert!(group(vec![body(0x1000, &a), body(0x2000, &b)], 4).is_empty());
    }

    #[test]
    fn short_bodies_are_skipped() {
        let a = [0xC3, 0x90];
        assert!(group(vec![body(0x1000, &a), body(0x2000, &a)], 8).is_empty());
    }

    #[test]
    fn absolute_addresses_to_code_are_masked() {
        let mut with = [0u8; 16];
        with[..3].copy_from_slice(&[0x4C, 0x8B, 0x15]);
        with[3..7].copy_from_slice(&0x1800u32.to_le_bytes());
        let mut other = with;
        other[3..7].copy_from_slice(&0x1900u32.to_le_bytes());
        let (a, _) = mask(&with, 0x1000, &[(0x1000, 0x2000)]);
        let (b, _) = mask(&other, 0x1000, &[(0x1000, 0x2000)]);
        assert_eq!(a, b);
    }
}
