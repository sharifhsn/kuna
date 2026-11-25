//! Embedded Turso (`functions.db`) backend for `kuna decompile-project` and `kuna query`.

use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use kuna_console::engine::ConsoleProgram;
use kuna_console::project::{rva_of, FuncResult};
use turso::{Builder, Connection, Database, Statement, Value};

use crate::args::take_value;
use crate::jsonfmt::write_ascii_document;
use crate::project_shards::{rva_bucket, ProjectExportOpts};

pub const DB_FILE: &str = "functions.db";
const BATCH_ROWS: usize = 2048;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sections (
    idx INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    vma INTEGER NOT NULL,
    rva INTEGER NOT NULL,
    size INTEGER NOT NULL,
    kind TEXT NOT NULL,
    flags INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS functions (
    rva INTEGER PRIMARY KEY,
    va INTEGER NOT NULL,
    end_rva INTEGER NOT NULL,
    shard_rva INTEGER NOT NULL,
    shard_file TEXT,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    proto TEXT,
    code TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS function_aliases (
    rva INTEGER NOT NULL,
    alias TEXT NOT NULL,
    PRIMARY KEY (rva, alias)
);
CREATE TABLE IF NOT EXISTS function_callees (
    caller_rva INTEGER NOT NULL,
    callee_rva INTEGER NOT NULL,
    PRIMARY KEY (caller_rva, callee_rva)
);
CREATE TABLE IF NOT EXISTS types (
    name TEXT PRIMARY KEY,
    definition TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS globals (
    rva INTEGER PRIMARY KEY,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    declaration TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outlined_helpers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    module TEXT NOT NULL,
    head_rva INTEGER,
    proto TEXT,
    body TEXT NOT NULL,
    site_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outlined_sites (
    caller_rva INTEGER NOT NULL,
    head_rva INTEGER NOT NULL,
    exit_rva INTEGER NOT NULL,
    helper_id TEXT NOT NULL,
    PRIMARY KEY (caller_rva, head_rva)
);
"#;

const INDEXES_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_functions_va ON functions(va);
CREATE INDEX IF NOT EXISTS idx_functions_shard ON functions(shard_rva);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_callees_callee ON function_callees(callee_rva);
"#;

fn build_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| format!("cannot start Turso runtime: {e}"))
}

fn opt_text(s: Option<&str>) -> Value {
    match s {
        Some(v) => Value::Text(v.to_string()),
        None => Value::Null,
    }
}

/// Single-writer batched Turso exporter for `functions.db`.
pub struct ProjectDbWriter {
    rt: tokio::runtime::Runtime,
    _db: Database,
    conn: Connection,
    path: PathBuf,
    image_base: u64,
    shard_align: u64,
    stmt_func: Statement,
    stmt_alias: Statement,
    stmt_callee: Statement,
    in_tx: bool,
    pending_rows: usize,
    total_functions: usize,
}

impl ProjectDbWriter {
    pub fn create(
        path: &Path,
        image_base: u64,
        shard_align: u64,
    ) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", path.display()));
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }

        let rt = build_runtime()?;
        let path_str = path.to_string_lossy().into_owned();
        let (db, conn, stmt_func, stmt_alias, stmt_callee) = rt.block_on(async {
            let db = Builder::new_local(&path_str)
                .build()
                .await
                .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
            let conn = db
                .connect()
                .map_err(|e| format!("cannot connect {}: {e}", path.display()))?;
            let _ = conn.execute("PRAGMA synchronous = OFF", ()).await;
            let _ = conn.execute("PRAGMA cache_size = -65536", ()).await;
            conn.execute_batch(SCHEMA_SQL)
                .await
                .map_err(|e| format!("cannot initialize schema in {}: {e}", path.display()))?;
            let stmt_func = conn
                .prepare(
                    "INSERT OR REPLACE INTO functions \
                     (rva, va, end_rva, shard_rva, shard_file, name, size, proto, code, error) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .await
                .map_err(|e| format!("cannot prepare function insert: {e}"))?;
            let stmt_alias = conn
                .prepare("INSERT OR IGNORE INTO function_aliases (rva, alias) VALUES (?1, ?2)")
                .await
                .map_err(|e| format!("cannot prepare alias insert: {e}"))?;
            let stmt_callee = conn
                .prepare(
                    "INSERT OR IGNORE INTO function_callees (caller_rva, callee_rva) VALUES (?1, ?2)",
                )
                .await
                .map_err(|e| format!("cannot prepare callee insert: {e}"))?;
            Ok::<_, String>((db, conn, stmt_func, stmt_alias, stmt_callee))
        })?;

        Ok(Self {
            rt,
            _db: db,
            conn,
            path: path.to_path_buf(),
            image_base,
            shard_align,
            stmt_func,
            stmt_alias,
            stmt_callee,
            in_tx: false,
            pending_rows: 0,
            total_functions: 0,
        })
    }

    pub fn write_program_metadata(
        &mut self,
        file_name: &str,
        path_label: &str,
        prog: &ConsoleProgram,
        opts: ProjectExportOpts,
    ) -> Result<(), String> {
        self.flush()?;
        let image_base = self.image_base;
        let meta = prog.image_metadata();
        let entry = meta
            .and_then(|m| m.entry)
            .map(|vma| prog.find_entry_at(vma).map_or(vma, |e| e.addr.get_offset()));

        let mut kv: Vec<(&str, String)> = vec![
            ("schema_version", "1".to_string()),
            ("binary", file_name.to_string()),
            ("path", path_label.to_string()),
            ("architecture", prog.description().to_string()),
            ("image_base", format!("0x{image_base:x}")),
            ("layout", opts.layout.as_str().to_string()),
            ("shard_align", format!("0x{:x}", opts.shard_align)),
        ];
        if let Some(entry_va) = entry {
            kv.push(("entry", format!("0x{entry_va:x}")));
            kv.push(("entry_rva", format!("0x{:x}", rva_of(entry_va, image_base))));
        }

        let sections: Vec<(i64, String, i64, i64, i64, String, i64)> = match meta {
            Some(m) if !m.sections.is_empty() => m
                .sections
                .iter()
                .enumerate()
                .map(|(idx, s)| {
                    (
                        idx as i64,
                        s.name.clone(),
                        s.vma as i64,
                        rva_of(s.vma, image_base) as i64,
                        s.size as i64,
                        s.kind.clone(),
                        i64::from(s.flags),
                    )
                })
                .collect(),
            _ => prog
                .sections()
                .into_iter()
                .enumerate()
                .map(|(idx, (vma, size, flags))| {
                    (
                        idx as i64,
                        format!("seg_{idx}"),
                        vma as i64,
                        rva_of(vma, image_base) as i64,
                        size as i64,
                        "segment".to_string(),
                        i64::from(flags),
                    )
                })
                .collect(),
        };

        self.rt.block_on(async {
            self.conn
                .execute("BEGIN IMMEDIATE", ())
                .await
                .map_err(|e| format!("cannot begin metadata tx: {e}"))?;
            let mut stmt_meta = self
                .conn
                .prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")
                .await
                .map_err(|e| format!("cannot prepare meta insert: {e}"))?;
            for (k, v) in kv {
                stmt_meta
                    .execute(vec![Value::Text(k.to_string()), Value::Text(v)])
                    .await
                    .map_err(|e| format!("cannot insert meta {k}: {e}"))?;
            }
            let mut stmt_sec = self
                .conn
                .prepare(
                    "INSERT OR REPLACE INTO sections (idx, name, vma, rva, size, kind, flags) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .await
                .map_err(|e| format!("cannot prepare section insert: {e}"))?;
            for (idx, name, vma, rva, size, kind, flags) in sections {
                stmt_sec
                    .execute(vec![
                        Value::Integer(idx),
                        Value::Text(name),
                        Value::Integer(vma),
                        Value::Integer(rva),
                        Value::Integer(size),
                        Value::Text(kind),
                        Value::Integer(flags),
                    ])
                    .await
                    .map_err(|e| format!("cannot insert section {idx}: {e}"))?;
            }
            self.conn
                .execute("COMMIT", ())
                .await
                .map_err(|e| format!("cannot commit metadata tx: {e}"))?;
            Ok::<_, String>(())
        })
    }

    pub fn insert_function(
        &mut self,
        func: &FuncResult,
        shard_file: Option<&str>,
    ) -> Result<(), String> {
        let rva = rva_of(func.address, self.image_base);
        let size_u64 = u64::try_from(func.size).unwrap_or(0);
        let end_rva = rva.saturating_add(size_u64);
        let shard_rva = rva_bucket(rva, self.shard_align);
        self.insert_function_raw(
            rva,
            func.address,
            end_rva,
            shard_rva,
            shard_file,
            &func.name,
            func.size,
            func.proto.as_deref(),
            func.code.as_deref(),
            func.error.as_deref(),
            &func.aliases,
            &func.callee_hints,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_function_raw(
        &mut self,
        rva: u64,
        va: u64,
        end_rva: u64,
        shard_rva: u64,
        shard_file: Option<&str>,
        name: &str,
        size: i64,
        proto: Option<&str>,
        code: Option<&str>,
        error: Option<&str>,
        aliases: &[String],
        callee_vas: &[u64],
    ) -> Result<(), String> {
        let image_base = self.image_base;
        let need_begin = !self.in_tx;
        let will_commit = self.pending_rows + 1 >= BATCH_ROWS;

        self.rt.block_on(async {
            if need_begin {
                self.conn
                    .execute("BEGIN IMMEDIATE", ())
                    .await
                    .map_err(|e| format!("cannot begin batch tx: {e}"))?;
            }
            self.stmt_func
                .execute(vec![
                    Value::Integer(rva as i64),
                    Value::Integer(va as i64),
                    Value::Integer(end_rva as i64),
                    Value::Integer(shard_rva as i64),
                    opt_text(shard_file),
                    Value::Text(name.to_string()),
                    Value::Integer(size),
                    opt_text(proto),
                    opt_text(code),
                    opt_text(error),
                ])
                .await
                .map_err(|e| format!("cannot insert function 0x{rva:x}: {e}"))?;

            for alias in aliases {
                self.stmt_alias
                    .execute(vec![Value::Integer(rva as i64), Value::Text(alias.clone())])
                    .await
                    .map_err(|e| format!("cannot insert alias for 0x{rva:x}: {e}"))?;
            }
            for &callee_va in callee_vas {
                let callee_rva = rva_of(callee_va, image_base);
                self.stmt_callee
                    .execute(vec![Value::Integer(rva as i64), Value::Integer(callee_rva as i64)])
                    .await
                    .map_err(|e| format!("cannot insert callee for 0x{rva:x}: {e}"))?;
            }
            if will_commit {
                self.conn
                    .execute("COMMIT", ())
                    .await
                    .map_err(|e| format!("cannot commit batch tx: {e}"))?;
            }
            Ok::<_, String>(())
        })?;

        self.total_functions += 1;
        if will_commit {
            self.in_tx = false;
            self.pending_rows = 0;
        } else {
            self.in_tx = true;
            self.pending_rows += 1;
        }
        Ok(())
    }

    pub fn write_types_and_globals(
        &mut self,
        types_text: &str,
        results: &[FuncResult],
    ) -> Result<(), String> {
        self.flush()?;
        let parsed_types = split_c_type_definitions(types_text);
        let mut globals: BTreeMap<u64, (u64, String, String)> = BTreeMap::new();
        for r in results {
            for g in &r.globals {
                let rva = rva_of(g.address, self.image_base);
                globals
                    .entry(rva)
                    .or_insert_with(|| (g.address, g.name.clone(), g.declaration.clone()));
            }
        }
        if parsed_types.is_empty() && globals.is_empty() {
            return Ok(());
        }

        self.rt.block_on(async {
            self.conn
                .execute("BEGIN IMMEDIATE", ())
                .await
                .map_err(|e| format!("cannot begin types/globals tx: {e}"))?;
            let mut stmt_type = self
                .conn
                .prepare("INSERT OR REPLACE INTO types (name, definition) VALUES (?1, ?2)")
                .await
                .map_err(|e| format!("cannot prepare type insert: {e}"))?;
            for (name, def) in parsed_types {
                stmt_type
                    .execute(vec![Value::Text(name), Value::Text(def)])
                    .await
                    .map_err(|e| format!("cannot insert type: {e}"))?;
            }
            let mut stmt_global = self
                .conn
                .prepare(
                    "INSERT OR REPLACE INTO globals (rva, va, name, declaration) \
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .await
                .map_err(|e| format!("cannot prepare global insert: {e}"))?;
            for (rva, (va, name, decl)) in globals {
                stmt_global
                    .execute(vec![
                        Value::Integer(rva as i64),
                        Value::Integer(va as i64),
                        Value::Text(name),
                        Value::Text(decl),
                    ])
                    .await
                    .map_err(|e| format!("cannot insert global 0x{rva:x}: {e}"))?;
            }
            self.conn
                .execute("COMMIT", ())
                .await
                .map_err(|e| format!("cannot commit types/globals tx: {e}"))?;
            Ok::<_, String>(())
        })
    }

    pub fn flush(&mut self) -> Result<(), String> {
        if !self.in_tx {
            return Ok(());
        }
        self.rt.block_on(async {
            self.conn
                .execute("COMMIT", ())
                .await
                .map_err(|e| format!("cannot commit tx: {e}"))?;
            Ok::<_, String>(())
        })?;
        self.in_tx = false;
        self.pending_rows = 0;
        Ok(())
    }

    /// Flush open transactions, build secondary indexes, and return on-disk DB size.
    pub fn finalize(mut self) -> Result<u64, String> {
        self.flush()?;
        self.rt.block_on(async {
            self.conn
                .execute_batch(INDEXES_SQL)
                .await
                .map_err(|e| format!("cannot create secondary indexes: {e}"))?;
            let _ = self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", ()).await;
            Ok::<_, String>(())
        })?;
        let path = self.path.clone();
        drop(self);
        Ok(std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0))
    }
}

fn split_c_type_definitions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut seen_non_ws = false;
    let mut anon_idx = 0usize;

    for ch in text.chars() {
        if !seen_non_ws && ch.is_whitespace() {
            continue;
        }
        seen_non_ws = true;
        cur.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => depth = (depth - 1).max(0),
            ';' if depth == 0 => {
                let def = cur.trim().to_string();
                cur.clear();
                seen_non_ws = false;
                if def.is_empty() || def.starts_with("/*") {
                    continue;
                }
                let name = extract_c_type_name(&def).unwrap_or_else(|| {
                    anon_idx += 1;
                    format!("anon_type_{anon_idx}")
                });
                out.push((name, def));
            }
            _ => {}
        }
    }
    out
}

fn extract_c_type_name(def: &str) -> Option<String> {
    let head = def.split('{').next().unwrap_or(def).trim();
    for kw in ["struct ", "union ", "enum "] {
        if let Some(rest) = head.strip_prefix(kw) {
            let ident: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                return Some(format!("{}{ident}", kw));
            }
        }
    }
    let trimmed = def.trim_end_matches(';').trim();
    let last_tok: String = trimmed
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|tok| !tok.is_empty())
        .map(str::to_string)?;
    Some(last_tok)
}

// --- Read / query surface ----------------------------------------------------

const FUNCTION_COLUMNS: &str = "rva, va, end_rva, shard_rva, shard_file, name, size, proto, code, error";

fn hex_address<S: Serializer>(address: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{address:#x}"))
}

fn optional_hex_address<S: Serializer>(
    address: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match address {
        Some(value) => hex_address(value, serializer),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueriedFunction {
    #[serde(serialize_with = "hex_address")]
    pub rva: u64,
    #[serde(serialize_with = "hex_address")]
    pub va: u64,
    #[serde(serialize_with = "hex_address")]
    pub end_rva: u64,
    #[serde(serialize_with = "hex_address")]
    pub shard_rva: u64,
    pub shard_file: Option<String>,
    pub name: String,
    pub size: i64,
    pub proto: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueriedHelper {
    pub id: String,
    pub name: String,
    pub module: String,
    #[serde(serialize_with = "optional_hex_address")]
    pub head_rva: Option<u64>,
    pub proto: Option<String>,
    pub body: String,
    pub site_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DbCounts {
    pub functions: i64,
    pub sections: i64,
    pub types: i64,
    pub globals: i64,
    pub outlined_helpers: i64,
    pub outlined_sites: i64,
}

/// Read-only Turso connection wrapper for querying `functions.db`.
pub struct ProjectDbReader {
    rt: tokio::runtime::Runtime,
    _db: Database,
    conn: Connection,
}

impl ProjectDbReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("database not found: {}", path.display()));
        }
        let rt = build_runtime()?;
        let path_str = path.to_string_lossy().into_owned();
        let (db, conn) = rt.block_on(async {
            let db = Builder::new_local(&path_str)
                .read_only(true)
                .build()
                .await
                .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
            let conn = db
                .connect()
                .map_err(|e| format!("cannot connect {}: {e}", path.display()))?;
            Ok::<_, String>((db, conn))
        })?;
        Ok(Self { rt, _db: db, conn })
    }

    pub fn summary(&self) -> Result<(BTreeMap<String, String>, DbCounts), String> {
        self.rt.block_on(async {
            let mut meta = BTreeMap::new();
            let mut rows = self
                .conn
                .query("SELECT key, value FROM meta ORDER BY key", ())
                .await
                .map_err(|e| format!("query meta failed: {e}"))?;
            while let Some(row) = rows.next().await.map_err(|e| format!("read meta row: {e}"))? {
                if let (Ok(Value::Text(k)), Ok(Value::Text(v))) =
                    (row.get_value(0), row.get_value(1))
                {
                    meta.insert(k, v);
                }
            }
            let counts = DbCounts {
                functions: count_table(&self.conn, "functions").await?,
                sections: count_table(&self.conn, "sections").await?,
                types: count_table(&self.conn, "types").await?,
                globals: count_table(&self.conn, "globals").await?,
                outlined_helpers: count_table(&self.conn, "outlined_helpers").await?,
                outlined_sites: count_table(&self.conn, "outlined_sites").await?,
            };
            Ok::<_, String>((meta, counts))
        })
    }

    pub fn query_by_rva(&self, rva: u64) -> Result<Vec<QueriedFunction>, String> {
        self.rt.block_on(async {
            let mut exact = collect_functions(
                &self.conn,
                &format!("SELECT {FUNCTION_COLUMNS} FROM functions WHERE rva = ?1"),
                vec![Value::Integer(rva as i64)],
            )
            .await?;
            if !exact.is_empty() {
                return Ok(exact);
            }
            // Older exports also store u64 addresses as their signed SQLite bit pattern.
            // A positive start and negative end describe an extent crossing bit 63.
            let covering = if rva <= i64::MAX as u64 {
                "rva BETWEEN 0 AND ?1 AND (end_rva > ?1 OR end_rva < 0) ORDER BY rva DESC"
            } else {
                "(rva >= 0 OR rva <= ?1) AND end_rva < 0 AND end_rva > ?1 ORDER BY (rva < 0) DESC, rva DESC"
            };
            exact = collect_functions(
                &self.conn,
                &format!("SELECT {FUNCTION_COLUMNS} FROM functions WHERE {covering} LIMIT 1"),
                vec![Value::Integer(rva as i64)],
            )
            .await?;
            Ok(exact)
        })
    }

    pub fn query_by_range(
        &self,
        start_rva: u64,
        end_rva: u64,
        inclusive: bool,
    ) -> Result<Vec<QueriedFunction>, String> {
        if start_rva > end_rva {
            return Err("RVA range starts after its end".into());
        }
        let crosses_sign_bit = start_rva <= i64::MAX as u64 && end_rva > i64::MAX as u64;
        let join = if crosses_sign_bit { "OR" } else { "AND" };
        let upper = if inclusive { "<=" } else { "<" };
        let order = if crosses_sign_bit { "(rva < 0), rva" } else { "rva" };
        let sql = format!(
            "SELECT {FUNCTION_COLUMNS} FROM functions WHERE rva >= ?1 {join} rva {upper} ?2 ORDER BY {order}"
        );
        self.rt.block_on(collect_functions(
            &self.conn,
            &sql,
            vec![Value::Integer(start_rva as i64), Value::Integer(end_rva as i64)],
        ))
    }

    pub fn query_by_name(&self, pattern: &str) -> Result<Vec<QueriedFunction>, String> {
        let has_wild = pattern.contains('%') || pattern.contains('*');
        let literal = pattern.replace('!', "!!").replace('_', "!_");
        let sql_pattern = if has_wild { literal.replace('*', "%") } else { format!("%{literal}%") };
        self.rt.block_on(collect_functions(
            &self.conn,
            &format!(
                "SELECT {FUNCTION_COLUMNS} FROM functions WHERE name LIKE ?1 ESCAPE '!' \
                 ORDER BY CASE WHEN name = ?2 THEN 0 ELSE 1 END, (rva < 0), rva"
            ),
            vec![Value::Text(sql_pattern), Value::Text(pattern.to_string())],
        ))
    }

    pub fn query_helpers(&self) -> Result<Vec<QueriedHelper>, String> {
        self.rt.block_on(async {
            let mut rows = self
                .conn
                .query(
                    "SELECT id, name, module, head_rva, proto, body, site_count \
                     FROM outlined_helpers ORDER BY module, name",
                    (),
                )
                .await
                .map_err(|e| format!("query outlined_helpers failed: {e}"))?;
            let mut out = Vec::new();
            while let Some(row) = rows.next().await.map_err(|e| format!("read helper row: {e}"))? {
                out.push(QueriedHelper {
                    id: val_string(row.get_value(0))?,
                    name: val_string(row.get_value(1))?,
                    module: val_string(row.get_value(2))?,
                    head_rva: val_opt_i64(row.get_value(3))?.map(|v| v as u64),
                    proto: val_opt_string(row.get_value(4))?,
                    body: val_string(row.get_value(5))?,
                    site_count: val_i64(row.get_value(6))?,
                });
            }
            Ok(out)
        })
    }
}

async fn count_table(conn: &Connection, table: &str) -> Result<i64, String> {
    let mut rows = conn
        .query(&format!("SELECT COUNT(*) FROM {table}"), ())
        .await
        .map_err(|e| format!("count {table} failed: {e}"))?;
    if let Some(row) = rows.next().await.map_err(|e| format!("read count {table}: {e}"))? {
        return val_i64(row.get_value(0));
    }
    Ok(0)
}

async fn collect_functions(
    conn: &Connection,
    sql: &str,
    params: Vec<Value>,
) -> Result<Vec<QueriedFunction>, String> {
    let mut rows = conn
        .query(sql, params)
        .await
        .map_err(|e| format!("query functions failed: {e}"))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(|e| format!("read function row: {e}"))? {
        out.push(QueriedFunction {
            rva: val_i64(row.get_value(0))? as u64,
            va: val_i64(row.get_value(1))? as u64,
            end_rva: val_i64(row.get_value(2))? as u64,
            shard_rva: val_i64(row.get_value(3))? as u64,
            shard_file: val_opt_string(row.get_value(4))?,
            name: val_string(row.get_value(5))?,
            size: val_i64(row.get_value(6))?,
            proto: val_opt_string(row.get_value(7))?,
            code: val_opt_string(row.get_value(8))?,
            error: val_opt_string(row.get_value(9))?,
        });
    }
    Ok(out)
}

fn val_i64(res: turso::Result<Value>) -> Result<i64, String> {
    match res.map_err(|e| format!("column read error: {e}"))? {
        Value::Integer(v) => Ok(v),
        other => Err(format!("expected integer column, got {other:?}")),
    }
}

fn val_opt_i64(res: turso::Result<Value>) -> Result<Option<i64>, String> {
    match res.map_err(|e| format!("column read error: {e}"))? {
        Value::Null => Ok(None),
        Value::Integer(v) => Ok(Some(v)),
        other => Err(format!("expected nullable integer column, got {other:?}")),
    }
}

fn val_string(res: turso::Result<Value>) -> Result<String, String> {
    match res.map_err(|e| format!("column read error: {e}"))? {
        Value::Text(s) => Ok(s),
        other => Err(format!("expected text column, got {other:?}")),
    }
}

fn val_opt_string(res: turso::Result<Value>) -> Result<Option<String>, String> {
    match res.map_err(|e| format!("column read error: {e}"))? {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s)),
        other => Err(format!("expected nullable text column, got {other:?}")),
    }
}

// --- `kuna query` CLI --------------------------------------------------------

fn parse_addr(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid hex address {raw:?}"))
    } else {
        s.parse::<u64>().map_err(|_| format!("invalid address {raw:?}"))
    }
}

fn parse_range(raw: &str) -> Result<(u64, u64, bool), String> {
    if let Some((a, b)) = raw.split_once("..=") {
        let start = parse_addr(a)?;
        let end = parse_addr(b)?;
        if start > end {
            return Err(format!("invalid --range {raw:?}: start > end"));
        }
        return Ok((start, end, true));
    }
    if let Some((a, b)) = raw.split_once("..") {
        let start = parse_addr(a)?;
        let end = parse_addr(b)?;
        if start > end {
            return Err(format!("invalid --range {raw:?}: start > end"));
        }
        return Ok((start, end, false));
    }
    Err(format!("invalid --range {raw:?}: expected 0xSTART..0xEND or 0xSTART..=0xEND"))
}

fn usage_query() {
    eprintln!(
        "usage: kuna query <db> [--rva 0x...] [--range 0xA..0xB] [--name PATTERN] [--helpers] [--json]\n\
         \n\
         Query an embedded Turso project database (`functions.db` or a project folder\n\
         containing one) written by `kuna decompile-project --layout turso|both`.\n\
         \n\
         \x20 --rva 0xRVA         look up the function at (or containing) RVA\n\
         \x20 --range 0xA..0xB    list functions with RVA in [A, B) (or 0xA..=0xB inclusive)\n\
         \x20 --name PATTERN      match function names (substring, or * / % wildcards)\n\
         \x20 --helpers           list outlined helpers recorded in the database\n\
         \x20 --json              emit {{db,meta,counts,functions,helpers}}\n\
         \n\
         With no filter flags, prints the database metadata and table counts."
    );
}

pub fn run_query(argv: &[String]) -> i32 {
    let mut db_arg: Option<String> = None;
    let mut rva: Option<u64> = None;
    let mut range: Option<(u64, u64, bool)> = None;
    let mut name: Option<String> = None;
    let mut helpers = false;
    let mut json = false;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-h" | "--help" => {
                usage_query();
                return 0;
            }
            "--rva" => match take_value(argv, &mut i, "--rva").and_then(|v| parse_addr(&v)) {
                Ok(v) => rva = Some(v),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            },
            "--range" => match take_value(argv, &mut i, "--range").and_then(|v| parse_range(&v)) {
                Ok(v) => range = Some(v),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            },
            "--name" => match take_value(argv, &mut i, "--name") {
                Ok(v) => name = Some(v),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            },
            "--helpers" => helpers = true,
            "--json" => json = true,
            s if s.starts_with("--") => {
                eprintln!("error: unknown option {s}");
                usage_query();
                return 2;
            }
            other => {
                if db_arg.is_some() {
                    eprintln!("error: unexpected argument {other:?}");
                    usage_query();
                    return 2;
                }
                db_arg = Some(other.to_string());
            }
        }
        i += 1;
    }

    let Some(db_arg) = db_arg else {
        eprintln!("error: missing <db> path");
        usage_query();
        return 2;
    };
    let filters = usize::from(rva.is_some())
        + usize::from(range.is_some())
        + usize::from(name.is_some())
        + usize::from(helpers);
    if filters > 1 {
        eprintln!("error: --rva, --range, --name, and --helpers are mutually exclusive");
        return 2;
    }

    let mut db_path = PathBuf::from(&db_arg);
    if db_path.is_dir() {
        db_path = db_path.join(DB_FILE);
    }

    let document = match QueryDocument::read(&db_path, rva, range, name.as_deref(), helpers) {
        Ok(document) => document,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };

    let written = crate::output::emit_streamed(|out| {
        if json {
            write_ascii_document(out, &document)
        } else {
            document.write_text(out, filters == 0)
        }
    });
    written.map_or_else(|error| crate::output::status_after(error, 0), |()| 0)
}

#[derive(Serialize)]
struct QueryDocument {
    db: String,
    meta: BTreeMap<String, String>,
    counts: DbCounts,
    functions: Vec<QueriedFunction>,
    helpers: Vec<QueriedHelper>,
}

impl QueryDocument {
    fn read(
        path: &Path,
        rva: Option<u64>,
        range: Option<(u64, u64, bool)>,
        name: Option<&str>,
        helpers: bool,
    ) -> Result<Self, String> {
        let reader = ProjectDbReader::open(path)?;
        let (meta, counts) = reader.summary()?;
        let functions = if let Some(target) = rva {
            reader.query_by_rva(target)?
        } else if let Some((start, end, inclusive)) = range {
            reader.query_by_range(start, end, inclusive)?
        } else if let Some(pattern) = name {
            reader.query_by_name(pattern)?
        } else {
            Vec::new()
        };
        let helpers = if helpers {
            reader.query_helpers()?
        } else {
            Vec::new()
        };
        Ok(Self {
            db: path.display().to_string(),
            meta,
            counts,
            functions,
            helpers,
        })
    }

    fn write_text(&self, out: &mut dyn Write, summary: bool) -> io::Result<()> {
        if summary {
            writeln!(out, "database: {}", self.db)?;
            for (key, value) in &self.meta {
                writeln!(out, "  {key}: {value}")?;
            }
            let counts = &self.counts;
            writeln!(
                out,
                "  counts: {} functions, {} sections, {} types, {} globals, {} helpers, {} sites",
                counts.functions, counts.sections, counts.types, counts.globals,
                counts.outlined_helpers, counts.outlined_sites
            )?;
        }
        for helper in &self.helpers {
            writeln!(
                out, "// Helper: {} [{}] (id={}, sites={})\n{}\n",
                helper.name, helper.module, helper.id, helper.site_count, helper.body
            )?;
        }
        for function in &self.functions {
            writeln!(
                out, "// Function: {} @ 0x{:x} (rva 0x{:x}..0x{:x}, size {})",
                function.name, function.va, function.rva, function.end_rva, function.size
            )?;
            if let Some(code) = &function.code {
                writeln!(out, "{code}\n")?;
            } else if let Some(error) = &function.error {
                writeln!(out, "// error: {error}\n")?;
            } else if let Some(proto) = &function.proto {
                writeln!(out, "{proto}\n")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_turso_db_and_queries() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join(DB_FILE);
        let mut writer = ProjectDbWriter::create(&db_path, 0x14000_0000, 0x10000).unwrap();
        writer
            .insert_function_raw(
                0x1000,
                0x14000_1000,
                0x1040,
                0x0,
                Some("slabs/rva_00000000.c"),
                "entry_fn",
                0x40,
                Some("int entry_fn(void);"),
                Some("int entry_fn(void) { return helper_fn(); }"),
                None,
                &["start_alias".to_string()],
                &[0x14001_2000],
            )
            .unwrap();
        writer
            .insert_function_raw(
                0x12000,
                0x14001_2000,
                0x12020,
                0x10000,
                Some("slabs/rva_00010000.c"),
                "helper_fn",
                0x20,
                Some("int helper_fn(void);"),
                Some("int helper_fn(void) { return 42; }"),
                None,
                &[],
                &[],
            )
            .unwrap();
        let size = writer.finalize().unwrap();
        assert!(size > 0);

        let reader = ProjectDbReader::open(&db_path).unwrap();
        let (_, counts) = reader.summary().unwrap();
        assert_eq!(counts.functions, 2);

        let exact = reader.query_by_rva(0x1000).unwrap();
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].name, "entry_fn");
        assert_eq!(exact[0].va, 0x14000_1000);

        let interior = reader.query_by_rva(0x1018).unwrap();
        assert_eq!(interior.len(), 1);
        assert_eq!(interior[0].name, "entry_fn");

        let range = reader.query_by_range(0x10000, 0x20000, false).unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].name, "helper_fn");

        let by_name = reader.query_by_name("helper").unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].rva, 0x12000);
    }

    #[test]
    fn splits_c_type_definitions() {
        let defs = split_c_type_definitions(
            "struct Foo {\n  int a;\n};\n\ntypedef unsigned int u32;\n",
        );
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].0, "struct Foo");
        assert_eq!(defs[1].0, "u32");
    }
}
