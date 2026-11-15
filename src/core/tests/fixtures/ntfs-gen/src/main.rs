//! Builds the synthetic NTFS volume used by rv-triage's raw NTFS tests.
//!
//! Every byte of file content is synthetic (fixed patterns, no personal data). The volume is formatted and
//! populated with `rust-fs-ntfs` (MIT OR Apache-2.0), a pure-Rust NTFS writer: no GPL tool is involved.
//!
//! Usage: `cargo run --release -- <out.img.gz>` (writes the gzip-compressed volume image).

use fs_ntfs::block_io::PathIo;
use fs_ntfs::facade::Filesystem;
use fs_ntfs::mkfs::format_filesystem;
use fs_ntfs::write::{self, FileTimes};
use std::io::Write;
use std::path::Path;

const VOL_SIZE: u64 = 16 * 1024 * 1024;
const CLUSTER: u32 = 4096;
const RECORD: u32 = 4096;
const SERIAL: u64 = 0x5256_5452_4941_4745; // "RVTRIAGE"

/// 100 ns intervals since 1601-01-01 for a UTC unix time.
fn nt(unix: u64) -> u64 {
    (unix + 11_644_473_600) * 10_000_000
}

/// Deterministic, obviously synthetic bytes.
fn pattern(tag: &str, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut i = 0u32;
    while v.len() < len {
        v.extend_from_slice(format!("{}:{:08}\n", tag, i).as_bytes());
        i += 1;
    }
    v.truncate(len);
    v
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: ntfsgen <out.img.gz>");
    let tmp = format!("{}.raw", out);
    let img = Path::new(&tmp);
    {
        let f = std::fs::File::create(img).unwrap();
        f.set_len(VOL_SIZE).unwrap();
    }
    {
        let mut io = PathIo::open_rw(img).unwrap();
        format_filesystem(&mut io, VOL_SIZE, CLUSTER, RECORD, Some("RVTRIAGE"), Some(SERIAL)).unwrap();
        fs_ntfs::block_io::BlockIo::sync(&mut io).unwrap();
    }
    let fs = Filesystem::mount(img).unwrap();

    let mut paths: Vec<String> = vec![];
    let mkdir = |parent: &str, name: &str, paths: &mut Vec<String>| {
        fs.mkdir(parent, name).unwrap_or_else(|e| panic!("mkdir {parent}/{name}: {e}"));
        paths.push(format!("{}/{}", parent.trim_end_matches('/'), name));
    };
    for (parent, name) in [
        ("/", "Windows"),
        ("/Windows", "System32"),
        ("/Windows/System32", "config"),
        ("/Windows/System32", "winevt"),
        ("/Windows/System32/winevt", "Logs"),
        ("/Windows/System32", "Tasks"),
        ("/Windows/System32/Tasks", "Microsoft"),
        ("/Windows", "Prefetch"),
        ("/", "Users"),
        ("/Users", "ana"),
        ("/Users/ana", "AppData"),
        ("/Users/ana/AppData", "Local"),
        ("/Users/ana/AppData/Local", "Microsoft"),
        ("/Users/ana/AppData/Local/Microsoft", "Edge"),
        ("/Users/ana/AppData/Local/Microsoft/Edge", "User Data"),
        ("/Users/ana/AppData/Local/Microsoft/Edge/User Data", "Default"),
        // A junction (mount point reparse point) like Windows' legacy "Application Data" link: never followed.
        ("/Users/ana/AppData/Local", "Application Data"),
        ("/Users/ana", "Documents"),
    ] {
        mkdir(parent, name, &mut paths);
    }

    let file = |path: &str, data: &[u8], paths: &mut Vec<String>| {
        let (parent, name) = path.rsplit_once('/').unwrap();
        let parent = if parent.is_empty() { "/" } else { parent };
        fs.create_file(parent, name).unwrap_or_else(|e| panic!("create {path}: {e}"));
        if !data.is_empty() {
            fs.write_file_contents(path, data).unwrap_or_else(|e| panic!("write {path}: {e}"));
        }
        paths.push(path.to_string());
    };
    let mut system = b"regf".to_vec();
    system.extend(pattern("SYNTHETIC-SYSTEM-HIVE", 12 * 1024 - 4));
    file("/Windows/System32/config/SYSTEM", &system, &mut paths);
    file("/Windows/System32/config/SYSTEM.LOG1", b"log1", &mut paths);
    file("/Windows/System32/config/SOFTWARE", b"regf-software", &mut paths);
    let mut evtx = b"ElfFile\0".to_vec();
    evtx.extend(pattern("SYNTHETIC-EVTX", 16 * 1024 - 8));
    file("/Windows/System32/winevt/Logs/Security.evtx", &evtx, &mut paths);
    file("/Windows/System32/winevt/Logs/Empty.evtx", b"", &mut paths);
    file("/Windows/System32/Tasks/Updater", b"<Task/>", &mut paths);
    file("/Windows/System32/Tasks/Microsoft/Defrag", b"<Task>defrag</Task>", &mut paths);
    // Enough prefetch files that the folder index needs an $INDEX_ALLOCATION.
    for i in 0..40 {
        let p = format!("/Windows/Prefetch/APP{:04}.EXE-{:08X}.pf", i, 0x0BD3_0981u32 + i);
        file(&p, format!("MAMpf synthetic {}", i).as_bytes(), &mut paths);
    }
    file("/Windows/Prefetch/CMD.EXE-0BD30981.pf", b"MAMpf", &mut paths);
    let mut hist = b"SQLite format 3\0".to_vec();
    hist.extend(pattern("SYNTHETIC-HISTORY", 8 * 1024 - 16));
    file(
        "/Users/ana/AppData/Local/Microsoft/Edge/User Data/Default/History",
        &hist,
        &mut paths,
    );
    file(
        "/Users/ana/Documents/\u{dc}n\u{ef}code-\u{f1}.txt",
        b"unicode name, synthetic",
        &mut paths,
    );

    // Sparse NTUSER.DAT: data in the first and last clusters, a hole between.
    {
        let path = "/Users/ana/NTUSER.DAT";
        fs.create_file("/Users/ana", "NTUSER.DAT").unwrap();
        let mut d = vec![0u8; 64 * 1024];
        d[..8].copy_from_slice(b"regf-ana");
        let n = d.len();
        d[n - 4..].copy_from_slice(b"tail");
        write::write_sparse_file(img, path, &d).unwrap();
        paths.push(path.into());
    }

    // Fragmented file whose valid data length is below its size: A is written, B is written after it, C (0xEE
    // bytes) is written and deleted so its clusters hold stale data, then A grows into them without writing.
    // A reader must return A's 8 KiB, then zeros (never the stale 0xEE bytes).
    {
        file("/Users/ana/Documents/frag-a.bin", &pattern("FRAG-A", 8 * 1024), &mut paths);
        file("/Users/ana/Documents/frag-b.bin", &pattern("FRAG-B", 8 * 1024), &mut paths);
        fs.create_file("/Users/ana/Documents", "stale.bin").unwrap();
        fs.write_file_contents("/Users/ana/Documents/stale.bin", &vec![0xEEu8; 16 * 1024])
            .unwrap();
        fs.unlink("/Users/ana/Documents/stale.bin").unwrap();
        fs.grow("/Users/ana/Documents/frag-a.bin", 20 * 1024).unwrap();
    }

    // Mount point reparse data: \??\C:\Users\ana\AppData\Local (substitute) + C:\Users\ana\AppData\Local (print).
    {
        let sub: Vec<u16> = r"\??\C:\Users\ana\AppData\Local".encode_utf16().collect();
        let prn: Vec<u16> = r"C:\Users\ana\AppData\Local".encode_utf16().collect();
        let mut d = vec![];
        let sl = (sub.len() * 2) as u16;
        let pl = (prn.len() * 2) as u16;
        for v in [0u16, sl, sl + 2, pl] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        for u in sub.iter().chain([0u16].iter()).chain(prn.iter()).chain([0u16].iter()) {
            d.extend_from_slice(&u.to_le_bytes());
        }
        fs.write_reparse_point("/Users/ana/AppData/Local/Application Data", 0xA000_0003, &d)
            .unwrap();
    }

    // Fixed $STANDARD_INFORMATION times (2026-01-02T03:04:05Z ... ).
    for p in &paths {
        write::set_times(
            img,
            p,
            FileTimes {
                creation: Some(nt(1_767_323_045)),
                modification: Some(nt(1_767_323_045 + 86_400)),
                mft_record_modification: Some(nt(1_767_323_045 + 2 * 86_400)),
                access: Some(nt(1_767_323_045 + 3 * 86_400)),
            },
        )
        .unwrap_or_else(|e| panic!("set_times {p}: {e}"));
    }
    drop(fs);

    let raw = std::fs::read(img).unwrap();
    let f = std::fs::File::create(&out).unwrap();
    let mut gz = flate2::GzBuilder::new().mtime(0).write(f, flate2::Compression::best());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap();
    std::fs::remove_file(img).unwrap();
}
