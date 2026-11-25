//! 300,000-function head-to-head profiling benchmark across project export layouts:
//! `single`, `rva-slab`, `rva-file`, and `turso`.
//!
//! Run with:
//! `cargo test --release -p kuna-cli --bin kuna project_bench -- --ignored --nocapture`

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::project_db::{ProjectDbReader, ProjectDbWriter, DB_FILE};
use crate::project_shards::{
    func_rel_path, rva_bucket, slab_rel_path, OutputLayout, ShardWriter, DEFAULT_SHARD_ALIGN,
};

const DEFAULT_N: usize = 300_000;
const IMAGE_BASE: u64 = 0x1_4000_0000;
const FUNC_STRIDE: u64 = 0x100;
const LOOKUP_SAMPLES: usize = 1_000;
const RANGE_SAMPLES: usize = 20;

fn bench_count() -> usize {
    std::env::var("KUNA_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_N)
}

fn bench_rva_file_count(total_n: usize) -> usize {
    std::env::var("KUNA_BENCH_RVA_FILE_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(total_n)
}

fn synth_block(idx: usize) -> (u64, u64, String, String, String) {
    let rva = 0x1000 + (idx as u64) * FUNC_STRIDE;
    let va = IMAGE_BASE + rva;
    let name = format!("sub_{va:x}");
    let proto = format!("int {name}(long long a1, int a2);");
    let code = format!(
        "int {name}(long long a1, int a2)\n\
         {{\n\
         \x20 long long v1 = *(long long *)(a1 + 0x10);\n\
         \x20 int acc = a2 ^ 0x{:x};\n\
         \x20 if (v1 != 0) {{\n\
         \x20   acc += *(int *)(v1 + 0x{:x});\n\
         \x20 }}\n\
         \x20 return acc + {};\n\
         }}",
        (idx * 2654435761) & 0xffff,
        (idx & 0x3f) * 4,
        idx & 0xff
    );
    (rva, va, name, proto, code)
}

fn format_c_block(name: &str, va: u64, code: &str) -> String {
    format!("// Function: {name} @ 0x{va:x}\n{code}\n\n")
}

fn read_proc_kb(field: &str) -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(tok) = rest.split_whitespace().next() {
                if let Ok(kb) = tok.parse::<u64>() {
                    return kb;
                }
            }
        }
    }
    0
}

fn walk_dir_stats(dir: &Path) -> (u64, u64, usize) {
    let mut logical_bytes = 0u64;
    let mut disk_bytes = 0u64;
    let mut inodes = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        inodes += 1;
        let Ok(rd) = std::fs::read_dir(&cur) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
            } else {
                inodes += 1;
                logical_bytes += meta.len();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    disk_bytes += meta.blocks() * 512;
                }
                #[cfg(not(unix))]
                {
                    disk_bytes += meta.len();
                }
            }
        }
    }
    (logical_bytes, disk_bytes, inodes)
}

fn percentiles_us(mut samples: Vec<Duration>) -> (f64, f64, f64) {
    samples.sort_unstable();
    let at = |pct: f64| -> f64 {
        let idx = (((samples.len().saturating_sub(1)) as f64) * pct).round() as usize;
        samples[idx.min(samples.len() - 1)].as_secs_f64() * 1_000_000.0
    };
    (at(0.50), at(0.95), at(0.99))
}

fn sample_indices(n: usize, count: usize) -> Vec<usize> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..count)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x as usize) % n
        })
        .collect()
}

struct BenchRow {
    layout: &'static str,
    n: usize,
    write_s: f64,
    fns_per_sec: f64,
    rss_mib: f64,
    hwm_mib: f64,
    logical_mib: f64,
    disk_mib: f64,
    inodes: usize,
    lookup_p50_us: f64,
    lookup_p95_us: f64,
    lookup_p99_us: f64,
    scan_64k_us: f64,
    scan_1m_us: f64,
    note: String,
}

fn make_temp_dir(tag: &str) -> tempfile::TempDir {
    if let Ok(base) = std::env::var("KUNA_BENCH_DIR") {
        let base_path = PathBuf::from(base);
        std::fs::create_dir_all(&base_path).unwrap();
        tempfile::Builder::new().prefix(tag).tempdir_in(base_path).unwrap()
    } else {
        tempfile::Builder::new().prefix(tag).tempdir().unwrap()
    }
}

fn bench_single(n: usize) -> BenchRow {
    let dir = make_temp_dir("kuna_bench_single_");
    let c_path = dir.path().join("app.exe.c");
    let idx_path = dir.path().join("index.jsonl");

    let t0 = Instant::now();
    let mut offsets: Vec<(u64, u64, usize)> = Vec::with_capacity(n);
    {
        let mut c_out = BufWriter::with_capacity(256 * 1024, File::create(&c_path).unwrap());
        let mut i_out = BufWriter::with_capacity(256 * 1024, File::create(&idx_path).unwrap());
        let header = "#include \"app.exe.h\"\n\n";
        c_out.write_all(header.as_bytes()).unwrap();
        let mut pos = header.len() as u64;
        for i in 0..n {
            let (rva, va, name, _proto, code) = synth_block(i);
            let block = format_c_block(&name, va, &code);
            c_out.write_all(block.as_bytes()).unwrap();
            let line = format!(
                "{{\"seq\":{i},\"name\":\"{name}\",\"addr\":\"0x{va:x}\",\"rva\":\"0x{rva:x}\",\
                 \"end_rva\":\"0x{:x}\",\"size\":256,\"c_file\":\"app.exe.c\",\
                 \"c_offset\":{pos},\"c_len\":{},\"error\":null}}\n",
                rva + FUNC_STRIDE,
                block.len()
            );
            i_out.write_all(line.as_bytes()).unwrap();
            offsets.push((rva, pos, block.len()));
            pos += block.len() as u64;
        }
        c_out.flush().unwrap();
        i_out.flush().unwrap();
    }
    let write_s = t0.elapsed().as_secs_f64();
    let (logical, disk, inodes) = walk_dir_stats(dir.path());
    let rss_mib = read_proc_kb("VmRSS:") as f64 / 1024.0;
    let hwm_mib = read_proc_kb("VmHWM:") as f64 / 1024.0;

    // Random single-RVA lookup via in-memory index + seek/read
    let mut file = File::open(&c_path).unwrap();
    let queries = sample_indices(n, LOOKUP_SAMPLES);
    let mut lookup_times = Vec::with_capacity(LOOKUP_SAMPLES);
    let mut buf = Vec::with_capacity(1024);
    for idx in queries {
        let target_rva = 0x1000 + (idx as u64) * FUNC_STRIDE;
        let q0 = Instant::now();
        let pos_idx = offsets.binary_search_by_key(&target_rva, |e| e.0).unwrap();
        let (_, off, len) = offsets[pos_idx];
        buf.resize(len, 0);
        file.seek(SeekFrom::Start(off)).unwrap();
        file.read_exact(&mut buf).unwrap();
        lookup_times.push(q0.elapsed());
    }
    let (p50, p95, p99) = percentiles_us(lookup_times);

    // Contiguous range scans (64 KiB and 1 MiB)
    let range_starts = sample_indices(n.saturating_sub(5000).max(1), RANGE_SAMPLES);
    let mut scan_64k = Vec::with_capacity(RANGE_SAMPLES);
    let mut scan_1m = Vec::with_capacity(RANGE_SAMPLES);
    for &idx in &range_starts {
        let start_rva = rva_bucket(0x1000 + (idx as u64) * FUNC_STRIDE, DEFAULT_SHARD_ALIGN);
        for (span, bucket_times) in [(0x10000u64, &mut scan_64k), (0x10_0000u64, &mut scan_1m)] {
            let end_rva = start_rva + span;
            let q0 = Instant::now();
            let lo = offsets.partition_point(|e| e.0 < start_rva);
            let hi = offsets.partition_point(|e| e.0 < end_rva);
            if lo < hi {
                let byte_start = offsets[lo].1;
                let byte_end = offsets[hi - 1].1 + offsets[hi - 1].2 as u64;
                let mut slice = vec![0u8; (byte_end - byte_start) as usize];
                file.seek(SeekFrom::Start(byte_start)).unwrap();
                file.read_exact(&mut slice).unwrap();
            }
            bucket_times.push(q0.elapsed());
        }
    }
    let avg = |v: &[Duration]| v.iter().map(|d| d.as_secs_f64() * 1e6).sum::<f64>() / v.len() as f64;

    BenchRow {
        layout: "single",
        n,
        write_s,
        fns_per_sec: n as f64 / write_s,
        rss_mib,
        hwm_mib,
        logical_mib: logical as f64 / (1024.0 * 1024.0),
        disk_mib: disk as f64 / (1024.0 * 1024.0),
        inodes,
        lookup_p50_us: p50,
        lookup_p95_us: p95,
        lookup_p99_us: p99,
        scan_64k_us: avg(&scan_64k),
        scan_1m_us: avg(&scan_1m),
        note: "requires index.jsonl in RAM for O(log N) seek".into(),
    }
}

fn bench_rva_slab(n: usize) -> BenchRow {
    let dir = make_temp_dir("kuna_bench_slab_");
    let t0 = Instant::now();
    let mut writer = ShardWriter::new(
        dir.path(),
        "app.exe",
        IMAGE_BASE,
        OutputLayout::RvaSlab,
        DEFAULT_SHARD_ALIGN,
        false,
    )
    .unwrap();
    for i in 0..n {
        let (rva, va, name, _proto, code) = synth_block(i);
        let block = format_c_block(&name, va, &code);
        writer.write_func(rva, rva + FUNC_STRIDE, &block).unwrap();
    }
    let summary = writer.finalize().unwrap();
    let write_s = t0.elapsed().as_secs_f64();
    let (logical, disk, inodes) = walk_dir_stats(dir.path());
    let rss_mib = read_proc_kb("VmRSS:") as f64 / 1024.0;
    let hwm_mib = read_proc_kb("VmHWM:") as f64 / 1024.0;

    // Zero-index single-RVA lookup: directly compute slab path and scan within the 64 KiB slab
    let queries = sample_indices(n, LOOKUP_SAMPLES);
    let mut lookup_times = Vec::with_capacity(LOOKUP_SAMPLES);
    for idx in queries {
        let target_rva = 0x1000 + (idx as u64) * FUNC_STRIDE;
        let va = IMAGE_BASE + target_rva;
        let bucket = rva_bucket(target_rva, DEFAULT_SHARD_ALIGN);
        let needle = format!("@ 0x{va:x}\n");
        let q0 = Instant::now();
        let path = dir.path().join(slab_rel_path(bucket));
        let content = std::fs::read_to_string(&path).unwrap();
        let pos = content.find(&needle).unwrap();
        std::hint::black_box(pos);
        lookup_times.push(q0.elapsed());
    }
    let (p50, p95, p99) = percentiles_us(lookup_times);

    // Contiguous range scans (1 slab for 64 KiB, 16 slabs for 1 MiB)
    let range_starts = sample_indices(n.saturating_sub(5000).max(1), RANGE_SAMPLES);
    let mut scan_64k = Vec::with_capacity(RANGE_SAMPLES);
    let mut scan_1m = Vec::with_capacity(RANGE_SAMPLES);
    for &idx in &range_starts {
        let start_bucket = rva_bucket(0x1000 + (idx as u64) * FUNC_STRIDE, DEFAULT_SHARD_ALIGN);
        let q0 = Instant::now();
        let s = std::fs::read(dir.path().join(slab_rel_path(start_bucket))).unwrap_or_default();
        std::hint::black_box(s.len());
        scan_64k.push(q0.elapsed());

        let q1 = Instant::now();
        let mut total = 0usize;
        for step in 0..16u64 {
            let b = start_bucket + step * DEFAULT_SHARD_ALIGN;
            let p = dir.path().join(slab_rel_path(b));
            if let Ok(bytes) = std::fs::read(&p) {
                total += bytes.len();
            }
        }
        std::hint::black_box(total);
        scan_1m.push(q1.elapsed());
    }
    let avg = |v: &[Duration]| v.iter().map(|d| d.as_secs_f64() * 1e6).sum::<f64>() / v.len() as f64;

    BenchRow {
        layout: "rva-slab",
        n,
        write_s,
        fns_per_sec: n as f64 / write_s,
        rss_mib,
        hwm_mib,
        logical_mib: logical as f64 / (1024.0 * 1024.0),
        disk_mib: disk as f64 / (1024.0 * 1024.0),
        inodes,
        lookup_p50_us: p50,
        lookup_p95_us: p95,
        lookup_p99_us: p99,
        scan_64k_us: avg(&scan_64k),
        scan_1m_us: avg(&scan_1m),
        note: format!("{} slabs (64-FD LRU cap, zero-index lookup)", summary.shard_count),
    }
}

fn bench_rva_file(n: usize) -> BenchRow {
    let dir = make_temp_dir("kuna_bench_file_");
    let t0 = Instant::now();
    let mut writer = ShardWriter::new(
        dir.path(),
        "app.exe",
        IMAGE_BASE,
        OutputLayout::RvaFile,
        DEFAULT_SHARD_ALIGN,
        false,
    )
    .unwrap();
    for i in 0..n {
        let (rva, va, name, _proto, code) = synth_block(i);
        let block = format_c_block(&name, va, &code);
        writer.write_func(rva, rva + FUNC_STRIDE, &block).unwrap();
    }
    let summary = writer.finalize().unwrap();
    let write_s = t0.elapsed().as_secs_f64();
    let (logical, disk, inodes) = walk_dir_stats(dir.path());
    let rss_mib = read_proc_kb("VmRSS:") as f64 / 1024.0;
    let hwm_mib = read_proc_kb("VmHWM:") as f64 / 1024.0;

    // Zero-lookup single-RVA open+read
    let queries = sample_indices(n, LOOKUP_SAMPLES);
    let mut lookup_times = Vec::with_capacity(LOOKUP_SAMPLES);
    for idx in queries {
        let target_rva = 0x1000 + (idx as u64) * FUNC_STRIDE;
        let bucket = rva_bucket(target_rva, DEFAULT_SHARD_ALIGN);
        let q0 = Instant::now();
        let content = std::fs::read_to_string(dir.path().join(func_rel_path(bucket, target_rva))).unwrap();
        std::hint::black_box(content.len());
        lookup_times.push(q0.elapsed());
    }
    let (p50, p95, p99) = percentiles_us(lookup_times);

    // Contiguous range scans (read every file in 1 bucket dir / 16 bucket dirs)
    let range_starts = sample_indices(n.saturating_sub(5000).max(1), RANGE_SAMPLES);
    let mut scan_64k = Vec::with_capacity(RANGE_SAMPLES);
    let mut scan_1m = Vec::with_capacity(RANGE_SAMPLES);
    for &idx in &range_starts {
        let start_bucket = rva_bucket(0x1000 + (idx as u64) * FUNC_STRIDE, DEFAULT_SHARD_ALIGN);
        let read_bucket = |b: u64| -> usize {
            let mut sum = 0usize;
            let bdir = dir.path().join(format!("funcs/rva_{b:08x}"));
            if let Ok(rd) = std::fs::read_dir(&bdir) {
                for e in rd.flatten() {
                    if let Ok(bytes) = std::fs::read(e.path()) {
                        sum += bytes.len();
                    }
                }
            }
            sum
        };
        let q0 = Instant::now();
        std::hint::black_box(read_bucket(start_bucket));
        scan_64k.push(q0.elapsed());

        let q1 = Instant::now();
        let mut total = 0usize;
        for step in 0..16u64 {
            total += read_bucket(start_bucket + step * DEFAULT_SHARD_ALIGN);
        }
        std::hint::black_box(total);
        scan_1m.push(q1.elapsed());
    }
    let avg = |v: &[Duration]| v.iter().map(|d| d.as_secs_f64() * 1e6).sum::<f64>() / v.len() as f64;

    BenchRow {
        layout: "rva-file",
        n,
        write_s,
        fns_per_sec: n as f64 / write_s,
        rss_mib,
        hwm_mib,
        logical_mib: logical as f64 / (1024.0 * 1024.0),
        disk_mib: disk as f64 / (1024.0 * 1024.0),
        inodes,
        lookup_p50_us: p50,
        lookup_p95_us: p95,
        lookup_p99_us: p99,
        scan_64k_us: avg(&scan_64k),
        scan_1m_us: avg(&scan_1m),
        note: format!("{} bucket dirs, 1 file/func (zero-lookup path)", summary.shard_count),
    }
}

fn bench_turso(n: usize) -> BenchRow {
    let dir = make_temp_dir("kuna_bench_turso_");
    let db_path = dir.path().join(DB_FILE);

    let t0 = Instant::now();
    let mut writer = ProjectDbWriter::create(&db_path, IMAGE_BASE, DEFAULT_SHARD_ALIGN).unwrap();
    for i in 0..n {
        let (rva, va, name, proto, code) = synth_block(i);
        let shard_rva = rva_bucket(rva, DEFAULT_SHARD_ALIGN);
        writer
            .insert_function_raw(
                rva,
                va,
                rva + FUNC_STRIDE,
                shard_rva,
                None,
                &name,
                FUNC_STRIDE as i64,
                Some(&proto),
                Some(&code),
                None,
                &[],
                &[],
            )
            .unwrap();
    }
    let _db_size = writer.finalize().unwrap();
    let write_s = t0.elapsed().as_secs_f64();
    let (logical, disk, inodes) = walk_dir_stats(dir.path());
    let rss_mib = read_proc_kb("VmRSS:") as f64 / 1024.0;
    let hwm_mib = read_proc_kb("VmHWM:") as f64 / 1024.0;

    let reader = ProjectDbReader::open(&db_path).unwrap();
    let queries = sample_indices(n, LOOKUP_SAMPLES);
    let mut lookup_times = Vec::with_capacity(LOOKUP_SAMPLES);
    for idx in queries {
        let target_rva = 0x1000 + (idx as u64) * FUNC_STRIDE;
        let q0 = Instant::now();
        let rows = reader.query_by_rva(target_rva).unwrap();
        assert_eq!(rows.len(), 1);
        std::hint::black_box(rows[0].code.as_ref().unwrap().len());
        lookup_times.push(q0.elapsed());
    }
    let (p50, p95, p99) = percentiles_us(lookup_times);

    let range_starts = sample_indices(n.saturating_sub(5000).max(1), RANGE_SAMPLES);
    let mut scan_64k = Vec::with_capacity(RANGE_SAMPLES);
    let mut scan_1m = Vec::with_capacity(RANGE_SAMPLES);
    for &idx in &range_starts {
        let start_rva = rva_bucket(0x1000 + (idx as u64) * FUNC_STRIDE, DEFAULT_SHARD_ALIGN);
        let q0 = Instant::now();
        let rows = reader.query_by_range(start_rva, start_rva + 0x10000, false).unwrap();
        std::hint::black_box(rows.len());
        scan_64k.push(q0.elapsed());

        let q1 = Instant::now();
        let rows = reader.query_by_range(start_rva, start_rva + 0x10_0000, false).unwrap();
        std::hint::black_box(rows.len());
        scan_1m.push(q1.elapsed());
    }
    let avg = |v: &[Duration]| v.iter().map(|d| d.as_secs_f64() * 1e6).sum::<f64>() / v.len() as f64;

    BenchRow {
        layout: "turso",
        n,
        write_s,
        fns_per_sec: n as f64 / write_s,
        rss_mib,
        hwm_mib,
        logical_mib: logical as f64 / (1024.0 * 1024.0),
        disk_mib: disk as f64 / (1024.0 * 1024.0),
        inodes,
        lookup_p50_us: p50,
        lookup_p95_us: p95,
        lookup_p99_us: p99,
        scan_64k_us: avg(&scan_64k),
        scan_1m_us: avg(&scan_1m),
        note: "batched 2048-row tx + deferred secondary indexes".into(),
    }
}

#[test]
#[ignore = "300k-function profiling benchmark; run explicitly with --ignored --nocapture"]
fn profile_300k_layouts() {
    let n = bench_count();
    let rva_file_n = bench_rva_file_count(n);
    eprintln!("\n=== Kuna Address-Keyed Output 300k Profiling Benchmark (N={n}, rva-file N={rva_file_n}) ===");
    let rows = [
        bench_single(n),
        bench_rva_slab(n),
        bench_rva_file(rva_file_n),
        bench_turso(n),
    ];

    println!();
    println!(
        "| {:<9} | {:>7} | {:>8} | {:>10} | {:>8} | {:>8} | {:>9} | {:>9} | {:>7} | {:>17} | {:>9} | {:>10} |",
        "Layout", "Funcs", "Write(s)", "Funcs/sec", "RSS(MiB)", "HWM(MiB)",
        "Size(MiB)", "Disk(MiB)", "Inodes", "Lookup p50/95/99us", "64K(us)", "1M(us)"
    );
    println!(
        "|{:-<11}|{:-<9}|{:-<10}|{:-<12}|{:-<10}|{:-<10}|{:-<11}|{:-<11}|{:-<9}|{:-<19}|{:-<11}|{:-<12}|",
        "", "", "", "", "", "", "", "", "", "", "", ""
    );
    for r in &rows {
        println!(
            "| {:<9} | {:>7} | {:>8.2} | {:>10.0} | {:>8.1} | {:>8.1} | {:>9.1} | {:>9.1} | {:>7} | {:>5.1}/{:>5.1}/{:>5.1} | {:>9.1} | {:>10.1} |",
            r.layout,
            r.n,
            r.write_s,
            r.fns_per_sec,
            r.rss_mib,
            r.hwm_mib,
            r.logical_mib,
            r.disk_mib,
            r.inodes,
            r.lookup_p50_us,
            r.lookup_p95_us,
            r.lookup_p99_us,
            r.scan_64k_us,
            r.scan_1m_us,
        );
    }
    println!();
    for r in &rows {
        println!("  - {}: {}", r.layout, r.note);
    }
}
