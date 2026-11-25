//! Memory-aligned RVA sharding for `kuna decompile-project`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::jsonfmt::{dumps_indent2, Json};

pub const DEFAULT_SHARD_ALIGN: u64 = 0x10000;
pub const MAX_OPEN_SHARD_FDS: usize = 64;
const SLAB_BUF_BYTES: usize = 16 * 1024;
pub const SHARDS_MANIFEST: &str = "shards.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputLayout {
    #[default]
    Single,
    RvaSlab,
    RvaFile,
    Turso,
    Both,
}

impl OutputLayout {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "single" => Ok(Self::Single),
            "rva-slab" => Ok(Self::RvaSlab),
            "rva-file" => Ok(Self::RvaFile),
            "turso" => Ok(Self::Turso),
            "both" => Ok(Self::Both),
            _ => Err(format!(
                "invalid --layout {raw:?}; expected single, rva-slab, rva-file, turso, or both"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::RvaSlab => "rva-slab",
            Self::RvaFile => "rva-file",
            Self::Turso => "turso",
            Self::Both => "both",
        }
    }

    pub fn writes_single_c(self) -> bool {
        matches!(self, Self::Single)
    }

    pub fn writes_slabs(self) -> bool {
        matches!(self, Self::RvaSlab | Self::Both)
    }

    pub fn writes_per_file(self) -> bool {
        matches!(self, Self::RvaFile)
    }

    pub fn writes_shards(self) -> bool {
        self.writes_slabs() || self.writes_per_file()
    }

    pub fn writes_turso(self) -> bool {
        matches!(self, Self::Turso | Self::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectExportOpts {
    pub layout: OutputLayout,
    pub shard_align: u64,
    pub no_asm: bool,
}

impl Default for ProjectExportOpts {
    fn default() -> Self {
        Self {
            layout: OutputLayout::Single,
            shard_align: DEFAULT_SHARD_ALIGN,
            no_asm: false,
        }
    }
}

pub fn parse_shard_align(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let value = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid --shard-align {raw:?}: expected hex or decimal integer"))?
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|_| format!("invalid --shard-align {raw:?}: expected hex or decimal integer"))?
    };
    if value == 0 || !value.is_power_of_two() {
        return Err(format!("--shard-align must be a non-zero power of 2, got {raw:?}"));
    }
    Ok(value)
}

pub fn rva_bucket(rva: u64, shard_align: u64) -> u64 {
    debug_assert!(shard_align.is_power_of_two());
    rva & !(shard_align - 1)
}

pub fn slab_rel_path(bucket: u64) -> String {
    format!("slabs/rva_{bucket:08x}.c")
}

pub fn func_rel_path(bucket: u64, rva: u64) -> String {
    format!("funcs/rva_{bucket:08x}/0x{rva:08x}.c")
}

#[derive(Debug, Clone)]
pub struct WriteReceipt {
    pub rel_path: String,
    pub offset: u64,
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct ShardSummary {
    pub shard_count: usize,
    pub total_bytes: u64,
    pub shards_json_bytes: usize,
}

#[derive(Debug, Clone)]
struct SlabMeta {
    rel_path: String,
    bytes: u64,
    func_count: usize,
    min_rva: u64,
    max_end_rva: u64,
}

/// Bounded-FD writer for `rva-slab` and `rva-file` layouts.
pub struct ShardWriter {
    out_dir: PathBuf,
    file_name: String,
    image_base: u64,
    layout: OutputLayout,
    shard_align: u64,
    flush_each: bool,
    max_open_fds: usize,
    slabs: BTreeMap<u64, SlabMeta>,
    open_slabs: BTreeMap<u64, BufWriter<File>>,
    lru: Vec<u64>,
    created_dirs: BTreeSet<u64>,
    written_func_files: BTreeMap<u64, u64>,
    total_functions: usize,
    total_bytes: u64,
}

impl ShardWriter {
    pub fn new(
        out_dir: &Path,
        file_name: &str,
        image_base: u64,
        layout: OutputLayout,
        shard_align: u64,
        flush_each: bool,
    ) -> Result<Self, String> {
        Self::with_max_open_fds(
            out_dir,
            file_name,
            image_base,
            layout,
            shard_align,
            flush_each,
            MAX_OPEN_SHARD_FDS,
        )
    }

    pub fn with_max_open_fds(
        out_dir: &Path,
        file_name: &str,
        image_base: u64,
        layout: OutputLayout,
        shard_align: u64,
        flush_each: bool,
        max_open_fds: usize,
    ) -> Result<Self, String> {
        if layout.writes_slabs() {
            let slabs_dir = out_dir.join("slabs");
            std::fs::create_dir_all(&slabs_dir)
                .map_err(|e| format!("cannot create {}: {e}", slabs_dir.display()))?;
        }
        if layout.writes_per_file() {
            let funcs_dir = out_dir.join("funcs");
            std::fs::create_dir_all(&funcs_dir)
                .map_err(|e| format!("cannot create {}: {e}", funcs_dir.display()))?;
        }
        Ok(Self {
            out_dir: out_dir.to_path_buf(),
            file_name: file_name.to_string(),
            image_base,
            layout,
            shard_align,
            flush_each,
            max_open_fds: max_open_fds.max(1),
            slabs: BTreeMap::new(),
            open_slabs: BTreeMap::new(),
            lru: Vec::new(),
            created_dirs: BTreeSet::new(),
            written_func_files: BTreeMap::new(),
            total_functions: 0,
            total_bytes: 0,
        })
    }

    pub fn write_func(&mut self, rva: u64, end_rva: u64, block: &str) -> Result<WriteReceipt, String> {
        let bucket = rva_bucket(rva, self.shard_align);
        if self.layout.writes_per_file() {
            self.write_per_file(bucket, rva, end_rva, block)
        } else {
            self.write_to_slab(bucket, rva, end_rva, block)
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[cfg(test)]
    pub fn open_fd_count(&self) -> usize {
        self.open_slabs.len()
    }

    fn touch_lru(&mut self, bucket: u64) {
        if let Some(pos) = self.lru.iter().position(|&b| b == bucket) {
            self.lru.remove(pos);
        }
        self.lru.push(bucket);
    }

    fn evict_if_full(&mut self) -> Result<(), String> {
        while self.open_slabs.len() >= self.max_open_fds {
            let Some(oldest) = self.lru.first().copied() else { break };
            self.lru.remove(0);
            if let Some(mut writer) = self.open_slabs.remove(&oldest) {
                writer
                    .flush()
                    .map_err(|e| format!("cannot flush {}: {e}", slab_rel_path(oldest)))?;
            }
        }
        Ok(())
    }

    fn write_to_slab(
        &mut self,
        bucket: u64,
        rva: u64,
        end_rva: u64,
        block: &str,
    ) -> Result<WriteReceipt, String> {
        let rel_path = slab_rel_path(bucket);
        let full_path = self.out_dir.join(&rel_path);

        if !self.open_slabs.contains_key(&bucket) {
            self.evict_if_full()?;
            if self.slabs.contains_key(&bucket) {
                let file = OpenOptions::new()
                    .append(true)
                    .open(&full_path)
                    .map_err(|e| format!("cannot reopen {}: {e}", full_path.display()))?;
                self.open_slabs.insert(bucket, BufWriter::with_capacity(SLAB_BUF_BYTES, file));
            } else {
                let file = File::create(&full_path)
                    .map_err(|e| format!("cannot create {}: {e}", full_path.display()))?;
                let mut writer = BufWriter::with_capacity(SLAB_BUF_BYTES, file);
                let header = format!("#include \"../{}.h\"\n\n", self.file_name);
                writer
                    .write_all(header.as_bytes())
                    .map_err(|e| format!("cannot write {}: {e}", full_path.display()))?;
                let header_len = header.len() as u64;
                self.total_bytes += header_len;
                self.slabs.insert(
                    bucket,
                    SlabMeta {
                        rel_path: rel_path.clone(),
                        bytes: header_len,
                        func_count: 0,
                        min_rva: rva,
                        max_end_rva: end_rva,
                    },
                );
                self.open_slabs.insert(bucket, writer);
            }
        }
        self.touch_lru(bucket);

        let writer = self.open_slabs.get_mut(&bucket).expect("slab writer just inserted");
        writer
            .write_all(block.as_bytes())
            .map_err(|e| format!("cannot append to {}: {e}", full_path.display()))?;
        if self.flush_each {
            writer
                .flush()
                .map_err(|e| format!("cannot flush {}: {e}", full_path.display()))?;
        }

        let meta = self.slabs.get_mut(&bucket).expect("slab meta just inserted");
        let offset = meta.bytes;
        let len = block.len();
        meta.bytes += len as u64;
        meta.func_count += 1;
        meta.min_rva = meta.min_rva.min(rva);
        meta.max_end_rva = meta.max_end_rva.max(end_rva);
        self.total_functions += 1;
        self.total_bytes += len as u64;

        Ok(WriteReceipt { rel_path, offset, len })
    }

    fn write_per_file(
        &mut self,
        bucket: u64,
        rva: u64,
        end_rva: u64,
        block: &str,
    ) -> Result<WriteReceipt, String> {
        if self.created_dirs.insert(bucket) {
            let bucket_dir = self.out_dir.join(format!("funcs/rva_{bucket:08x}"));
            std::fs::create_dir_all(&bucket_dir)
                .map_err(|e| format!("cannot create {}: {e}", bucket_dir.display()))?;
        }
        let rel_path = func_rel_path(bucket, rva);
        let full_path = self.out_dir.join(&rel_path);
        let len = block.len();

        let (offset, written_bytes) = if let Some(prev_len) = self.written_func_files.get_mut(&rva) {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&full_path)
                .map_err(|e| format!("cannot append to {}: {e}", full_path.display()))?;
            file.write_all(block.as_bytes())
                .map_err(|e| format!("cannot append to {}: {e}", full_path.display()))?;
            let off = *prev_len;
            *prev_len += len as u64;
            (off, len as u64)
        } else {
            let header = format!("#include \"../../{}.h\"\n\n", self.file_name);
            let mut content = String::with_capacity(header.len() + len);
            content.push_str(&header);
            content.push_str(block);
            std::fs::write(&full_path, content.as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", full_path.display()))?;
            let off = header.len() as u64;
            let total = content.len() as u64;
            self.written_func_files.insert(rva, total);
            (off, total)
        };

        let meta = self.slabs.entry(bucket).or_insert_with(|| SlabMeta {
            rel_path: format!("funcs/rva_{bucket:08x}"),
            bytes: 0,
            func_count: 0,
            min_rva: rva,
            max_end_rva: end_rva,
        });
        meta.bytes += written_bytes;
        meta.func_count += 1;
        meta.min_rva = meta.min_rva.min(rva);
        meta.max_end_rva = meta.max_end_rva.max(end_rva);
        self.total_functions += 1;
        self.total_bytes += written_bytes;

        Ok(WriteReceipt { rel_path, offset, len })
    }

    pub fn finalize(mut self) -> Result<ShardSummary, String> {
        for (bucket, mut writer) in std::mem::take(&mut self.open_slabs) {
            writer
                .flush()
                .map_err(|e| format!("cannot flush {}: {e}", slab_rel_path(bucket)))?;
        }
        self.lru.clear();

        let shards: Vec<Json> = self
            .slabs
            .iter()
            .map(|(&bucket, meta)| {
                Json::Object(vec![
                    ("bucket".into(), Json::Str(format!("0x{bucket:08x}"))),
                    ("file".into(), Json::Str(meta.rel_path.clone())),
                    ("functions".into(), Json::Number(meta.func_count.to_string())),
                    ("bytes".into(), Json::Number(meta.bytes.to_string())),
                    ("min_rva".into(), Json::Str(format!("0x{:x}", meta.min_rva))),
                    ("max_end_rva".into(), Json::Str(format!("0x{:x}", meta.max_end_rva))),
                ])
            })
            .collect();
        let manifest = Json::Object(vec![
            ("layout".into(), Json::Str(self.layout.as_str().into())),
            ("image_base".into(), Json::Str(format!("0x{:x}", self.image_base))),
            ("shard_align".into(), Json::Str(format!("0x{:x}", self.shard_align))),
            ("total_functions".into(), Json::Number(self.total_functions.to_string())),
            ("total_bytes".into(), Json::Number(self.total_bytes.to_string())),
            ("shard_count".into(), Json::Number(self.slabs.len().to_string())),
            ("shards".into(), Json::Array(shards)),
        ]);
        let text = format!("{}\n", dumps_indent2(&manifest));
        let manifest_path = self.out_dir.join(SHARDS_MANIFEST);
        std::fs::write(&manifest_path, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", manifest_path.display()))?;

        Ok(ShardSummary {
            shard_count: self.slabs.len(),
            total_bytes: self.total_bytes,
            shards_json_bytes: text.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shard_align_validates_power_of_two() {
        assert_eq!(parse_shard_align("0x10000").unwrap(), 0x10000);
        assert_eq!(parse_shard_align("65536").unwrap(), 65536);
        assert_eq!(parse_shard_align("0x1000").unwrap(), 0x1000);
        assert!(parse_shard_align("0").is_err());
        assert!(parse_shard_align("0x10001").is_err());
        assert!(parse_shard_align("12345").is_err());
        assert!(parse_shard_align("notanumber").is_err());
    }

    #[test]
    fn slab_writer_caps_open_fds_and_preserves_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = ShardWriter::with_max_open_fds(
            dir.path(),
            "app.exe",
            0x14000_0000,
            OutputLayout::RvaSlab,
            0x10000,
            false,
            8,
        )
        .unwrap();

        let mut receipts = Vec::new();
        for round in 0..2 {
            for slab_idx in 0..32u64 {
                let rva = slab_idx * 0x10000 + round * 0x100;
                let block = format!("// Function: f_{rva:x} @ 0x{:x}\nvoid f_{rva:x}(void) {{}}\n\n", 0x14000_0000 + rva);
                let receipt = writer.write_func(rva, rva + 0x40, &block).unwrap();
                assert!(writer.open_fd_count() <= 8, "open FDs exceeded cap");
                receipts.push((receipt, block));
            }
        }
        let summary = writer.finalize().unwrap();
        assert_eq!(summary.shard_count, 32);
        assert!(summary.total_bytes > 0);
        assert!(dir.path().join(SHARDS_MANIFEST).is_file());

        for (receipt, expected) in receipts {
            let content = std::fs::read(dir.path().join(&receipt.rel_path)).unwrap();
            let slice = &content[receipt.offset as usize..receipt.offset as usize + receipt.len];
            assert_eq!(std::str::from_utf8(slice).unwrap(), expected);
        }
    }

    #[test]
    fn rva_file_writer_creates_zero_lookup_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = ShardWriter::new(
            dir.path(),
            "app.exe",
            0x14000_0000,
            OutputLayout::RvaFile,
            0x10000,
            false,
        )
        .unwrap();
        let block = "// Function: main @ 0x140012340\nint main(void) { return 0; }\n\n";
        let receipt = writer.write_func(0x12340, 0x12380, block).unwrap();
        assert_eq!(receipt.rel_path, "funcs/rva_00010000/0x00012340.c");
        let summary = writer.finalize().unwrap();
        assert_eq!(summary.shard_count, 1);
        let content = std::fs::read_to_string(dir.path().join(&receipt.rel_path)).unwrap();
        assert!(content.starts_with("#include \"../../app.exe.h\"\n\n"));
        assert_eq!(&content[receipt.offset as usize..receipt.offset as usize + receipt.len], block);
    }
}
