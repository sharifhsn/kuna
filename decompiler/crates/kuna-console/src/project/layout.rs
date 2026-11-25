//! File and database layouts available for a project export.

pub const DEFAULT_SHARD_ALIGN: u64 = 0x10000;

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
