//! Raw NTFS source tests over two synthetic volume fixtures (`src/core/tests/fixtures`, provenance in NOTICE):
//! `ntfs-windows.img.gz` (generated with rust-fs-ntfs, Windows-like layout) and `ntfs-testfs1.img.gz` (the
//! `ntfs` crate's own test volume).

use super::*;
use crate::collect::copy::copy_one;
use crate::collect::{Group, Outcome, Resolved, SourceSpec, Target, targets};
use crate::hash::HashAlgo;
use std::io::{Cursor, Write};

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let mut out = vec![];
    flate2::read::GzDecoder::new(File::open(&p).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// The fixture written to a temporary image file (what `open_image` reads).
fn image_file(name: &str, bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join(name);
    File::create(&p).unwrap().write_all(bytes).unwrap();
    (d, p)
}

fn windows() -> (tempfile::TempDir, PathBuf) {
    image_file("evidence.dd", &fixture("ntfs-windows.img.gz"))
}

fn read_all(src: &dyn Source, path: &str) -> Vec<u8> {
    let mut o = src.open(path).unwrap();
    assert_eq!(o.method, ReadMethod::Raw);
    let mut b = vec![];
    o.reader.read_to_end(&mut b).unwrap();
    b
}

fn names(v: &[DirEntry]) -> Vec<String> {
    let mut n: Vec<String> = v.iter().map(|e| e.name.clone()).collect();
    n.sort();
    n
}

/// Same generator as the fixture's (tests/fixtures/ntfs-gen).
fn pattern(tag: &str, len: usize) -> Vec<u8> {
    let mut v = vec![];
    let mut i = 0u32;
    while v.len() < len {
        v.extend_from_slice(format!("{}:{:08}\n", tag, i).as_bytes());
        i += 1;
    }
    v.truncate(len);
    v
}

#[test]
fn image_describes_itself() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    assert_eq!(s.kind(), "image");
    assert_eq!(s.method(), ReadMethod::Raw);
    assert_eq!(s.display_prefix(), "evidence.dd:");
    let v = s.describe();
    assert_eq!(v["kind"], "image");
    assert_eq!(v["method"], "raw");
    assert_eq!(v["layout"], "volume");
    assert_eq!(v["bytes_per_sector"], 512);
    assert_eq!(v["cluster_size"], 4096);
    assert_eq!(v["total_size"], 16 * 1024 * 1024 - 512);
    assert_eq!(v["volume_serial"], "4941-4745");
    assert_eq!(v["volume_serial_64"], "5256545249414745");
    assert_eq!(v["volume_label"], "RVTRIAGE");
    assert!(
        v["ntfs_version"].as_str().unwrap().starts_with('3'),
        "{}",
        v
    );
    assert!(v["path"].as_str().unwrap().ends_with("evidence.dd"));
}

#[test]
fn lists_with_case_preserved_and_hides_metafiles() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    let root = s.list("").unwrap();
    assert_eq!(names(&root), vec!["Users", "Windows"], "{:?}", root);
    assert!(root.iter().all(|e| e.is_dir));
    let cfg = s.list("Windows/System32/config").unwrap();
    assert_eq!(names(&cfg), vec!["SOFTWARE", "SYSTEM", "SYSTEM.LOG1"]);
    assert!(cfg.iter().all(|e| !e.is_dir));
    // 41 entries: more than an $INDEX_ROOT holds, so the $INDEX_ALLOCATION is walked too.
    let pf = s.list("Windows/Prefetch").unwrap();
    assert_eq!(pf.len(), 41);
    assert!(pf.iter().any(|e| e.name == "CMD.EXE-0BD30981.pf"));
    assert!(pf.iter().any(|e| e.name == "APP0039.EXE-0BD309A8.pf"));
    assert!(s.list("Windows/System32/config/SYSTEM").is_err());
    assert_eq!(s.list("Nope").unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(s.list("../x").is_err());
}

#[test]
fn junctions_are_files_and_never_followed() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    let l = s.list("Users/ana/AppData/Local").unwrap();
    let j = l.iter().find(|e| e.name == "Application Data").unwrap();
    assert!(!j.is_dir);
    assert!(l.iter().find(|e| e.name == "Microsoft").unwrap().is_dir);
    assert!(s.list("Users/ana/AppData/Local/Application Data").is_err());
    let e = s
        .open("Users/ana/AppData/Local/Application Data")
        .err()
        .unwrap();
    assert!(e.kind() == io::ErrorKind::InvalidInput || e.kind() == io::ErrorKind::Unsupported);
    assert!(
        s.stat("Users/ana/AppData/Local/Application Data/Microsoft/Edge")
            .is_err()
    );
}

#[test]
fn stat_reports_times_record_and_size() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    let m = s.stat("Windows/System32/config/SYSTEM").unwrap();
    assert_eq!(m.size, 12 * 1024);
    assert!(m.mft_record.unwrap() >= 24);
    assert_eq!(
        m.si_created.as_deref(),
        Some("2026-01-02T03:04:05.0000000Z")
    );
    assert_eq!(
        m.si_modified.as_deref(),
        Some("2026-01-03T03:04:05.0000000Z")
    );
    assert_eq!(
        m.si_mft_changed.as_deref(),
        Some("2026-01-04T03:04:05.0000000Z")
    );
    assert_eq!(
        m.si_accessed.as_deref(),
        Some("2026-01-05T03:04:05.0000000Z")
    );
    for t in [
        &m.fn_created,
        &m.fn_modified,
        &m.fn_mft_changed,
        &m.fn_accessed,
    ] {
        let t = t.as_deref().unwrap();
        assert!(t.len() == 28 && t.ends_with('Z'), "{}", t);
    }
    assert!(!m.sparse && !m.compressed && !m.encrypted);
    assert_eq!(s.stat("Windows/System32/config/SYSTEM").unwrap(), m);
    assert_eq!(
        s.stat("Windows/System32/winevt/Logs/Empty.evtx")
            .unwrap()
            .size,
        0
    );
    assert!(s.stat("Windows/System32").is_err());
}

#[test]
fn lookup_is_case_insensitive_with_the_upcase_table() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    let a = s.stat("Windows/System32/config/SYSTEM").unwrap();
    let b = s.stat("wINDOWS/system32/CONFIG/system").unwrap();
    assert_eq!(a, b);
    // Non-ASCII: Ü/ü, Ï/ï, Ñ/ñ fold through $UpCase, not ASCII rules.
    let lower = read_all(&*s, "users/ANA/documents/\u{fc}n\u{ef}code-\u{f1}.txt");
    let upper = read_all(&*s, "Users/ana/Documents/\u{dc}N\u{cf}CODE-\u{d1}.TXT");
    assert_eq!(lower, b"unicode name, synthetic");
    assert_eq!(lower, upper);
    let docs = s.list("Users/ana/Documents").unwrap();
    assert!(
        docs.iter()
            .any(|e| e.name == "\u{dc}n\u{ef}code-\u{f1}.txt")
    );
}

#[test]
fn opens_resident_non_resident_sparse_and_fragmented_data() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    assert_eq!(read_all(&*s, "Windows/System32/Tasks/Updater"), b"<Task/>");
    let sys = read_all(&*s, "Windows/System32/config/SYSTEM");
    assert_eq!(&sys[..4], b"regf");
    assert_eq!(
        sys[4..],
        pattern("SYNTHETIC-SYSTEM-HIVE", 12 * 1024 - 4)[..]
    );
    assert!(read_all(&*s, "Windows/System32/winevt/Logs/Empty.evtx").is_empty());

    // Sparse: data, a hole read as zeros, data.
    let m = s.stat("Users/ana/NTUSER.DAT").unwrap();
    assert!(m.sparse);
    let n = read_all(&*s, "Users/ana/NTUSER.DAT");
    assert_eq!(n.len(), 64 * 1024);
    assert_eq!(&n[..8], b"regf-ana");
    assert!(n[8..n.len() - 4].iter().all(|b| *b == 0));
    assert_eq!(&n[n.len() - 4..], b"tail");

    // Fragmented, and grown past its valid data length over stale clusters: the tail reads as zeros.
    let f = read_all(&*s, "Users/ana/Documents/frag-a.bin");
    assert_eq!(f.len(), 20 * 1024);
    assert_eq!(f[..8 * 1024], pattern("FRAG-A", 8 * 1024)[..]);
    assert!(
        f[8 * 1024..].iter().all(|b| *b == 0),
        "stale bytes past the valid data length"
    );
    assert_eq!(
        read_all(&*s, "Users/ana/Documents/frag-b.bin"),
        pattern("FRAG-B", 8 * 1024)
    );

    // Small reads give the same bytes as one big read.
    let mut o = s.open("Windows/System32/config/SYSTEM").unwrap();
    let mut small = vec![];
    let mut b = [0u8; 777];
    loop {
        let k = o.reader.read(&mut b).unwrap();
        if k == 0 {
            break;
        }
        small.extend_from_slice(&b[..k]);
    }
    assert_eq!(small, sys);
}

/// Sets the COMPRESSED flag of a file's unnamed $DATA attribute in the image bytes.
fn mark_compressed(img: &mut [u8], path: &str) {
    let mut c = Cursor::new(img.to_vec());
    let mut n = ntfs::Ntfs::new(&mut c).unwrap();
    n.read_upcase_table(&mut c).unwrap();
    let mut cur = n.root_directory(&mut c).unwrap();
    for part in path.split('/') {
        let next = {
            let idx = cur.directory_index(&mut c).unwrap();
            let mut f = idx.finder();
            let e = ntfs::indexes::NtfsFileNameIndex::find(&mut f, &n, &mut c, part)
                .unwrap()
                .unwrap();
            e.to_file(&n, &mut c).unwrap()
        };
        cur = next;
    }
    let item = cur.data(&mut c, "").unwrap().unwrap();
    let pos = item
        .to_attribute()
        .unwrap()
        .position()
        .value()
        .unwrap()
        .get() as usize
        + 0x0C;
    assert!(pos % 512 < 510, "flag byte on an update sequence position");
    img[pos] |= 0x01;
}

#[test]
fn compressed_data_is_refused_not_misread() {
    let mut img = fixture("ntfs-windows.img.gz");
    mark_compressed(&mut img, "Users/ana/Documents/frag-b.bin");
    let (_d, p) = image_file("c.dd", &img);
    let s = open_image(&p).unwrap();
    assert!(s.stat("Users/ana/Documents/frag-b.bin").unwrap().compressed);
    let e = s.open("Users/ana/Documents/frag-b.bin").err().unwrap();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert!(e.to_string().contains("compressed"), "{}", e);
    // copy.rs reports it as not collected, with the reason.
    let pkg = tempfile::tempdir().unwrap();
    let o = copy_one(
        &*s,
        &Target {
            group: Group::Tasks,
            path: "Users/ana/Documents/frag-b.bin".into(),
        },
        pkg.path(),
        &[HashAlgo::Sha256],
        true,
        &mut |_| true,
    );
    let Outcome::NotCollected(nc) = o else {
        panic!("{:?}", o)
    };
    assert!(nc.reason.contains("compressed"), "{}", nc.reason);
}

#[test]
fn targets_resolve_on_the_image() {
    let (_d, p) = windows();
    let s = open_image(&p).unwrap();
    let r = targets::resolve(&*s, &Group::ALL, &[]);
    let files: Vec<String> = r
        .iter()
        .filter_map(|x| match x {
            Resolved::File(t) => Some(t.path.clone()),
            Resolved::Unlisted { .. } => None,
        })
        .collect();
    assert_eq!(files.len(), r.len(), "{:?}", r);
    for want in [
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SYSTEM.LOG1",
        "Windows/System32/config/SOFTWARE",
        "Windows/System32/winevt/Logs/Security.evtx",
        "Windows/System32/winevt/Logs/Empty.evtx",
        "Windows/Prefetch/CMD.EXE-0BD30981.pf",
        "Windows/System32/Tasks/Updater",
        "Windows/System32/Tasks/Microsoft/Defrag",
        "Users/ana/NTUSER.DAT",
        "Users/ana/AppData/Local/Microsoft/Edge/User Data/Default/History",
    ] {
        assert!(
            files.iter().any(|f| f == want),
            "{} not in {:?}",
            want,
            files
        );
    }
    // 3 hives + NTUSER + 2 evtx + 41 pf + 2 tasks + History
    assert_eq!(files.len(), 50, "{:?}", files);
}

#[test]
fn collection_run_over_an_image_packages_and_verifies() {
    use crate::events::Event;
    use crate::run::{RunConfig, run};
    use std::sync::atomic::AtomicBool;
    let (_d, p) = windows();
    let out = tempfile::tempdir().unwrap();
    let c = RunConfig {
        algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
        out_dir: out.path().into(),
        langs: vec!["en".into()],
        actor: "tester".into(),
        frontend: "test".into(),
        tool_name: "rv-triage".into(),
        tool_version: "0.0.0".into(),
        collect: Some(crate::collect::CollectOptions {
            source: SourceSpec::Image(p.clone()),
            groups: vec![Group::Hives, Group::Tasks, Group::Browsers],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut events = Vec::new();
    let s = run(
        &c,
        &mut |e: &Event| events.push(e.clone()),
        &AtomicBool::new(false),
    )
    .unwrap();
    // system.json + 4 hives + 2 tasks + History
    assert_eq!(s.items, 8, "{:?}", s);
    let pkg = s.report_dir.join("package");
    let sys = std::fs::read(pkg.join("artifacts/hives/Windows/System32/config/SYSTEM")).unwrap();
    assert_eq!(&sys[..4], b"regf");
    assert_eq!(sys.len(), 12 * 1024);
    assert_eq!(
        std::fs::read(pkg.join("artifacts/hives/Users/ana/NTUSER.DAT"))
            .unwrap()
            .len(),
        64 * 1024
    );
    let manifest = std::fs::read_to_string(pkg.join("manifest.json")).unwrap();
    assert!(manifest.contains("\"raw\""), "{}", manifest);
    assert!(manifest.contains("evidence.dd:"), "{}", manifest);
    let v = crate::verify::verify_log(&s.log_dir.join("audit.jsonl")).unwrap();
    assert!(v.problems.is_empty(), "{:?}", v.problems);
    let o = v.outputs.unwrap();
    assert_eq!(o.mismatched + o.missing + o.rejected, 0);
}

#[test]
fn upstream_test_volume_reads() {
    let (_d, p) = image_file("testfs1", &fixture("ntfs-testfs1.img.gz"));
    let s = open_image(&p).unwrap();
    let v = s.describe();
    assert_eq!(v["cluster_size"], 512);
    assert_eq!(v["volume_label"], "mylabel");
    let root = names(&s.list("").unwrap());
    for n in [
        "1000-bytes-file",
        "empty-file",
        "file-with-12345",
        "many_subdirs",
        "sparse-file",
    ] {
        assert!(root.iter().any(|r| r == n), "{} not in {:?}", n, root);
    }
    assert!(root.iter().all(|n| !n.starts_with('$')), "{:?}", root);
    let many = s.list("many_subdirs").unwrap();
    assert_eq!(many.len(), 512);
    assert!(many.iter().all(|e| e.is_dir));
    assert!(s.list("MANY_SUBDIRS/511").unwrap().is_empty());
    assert_eq!(read_all(&*s, "file-with-12345"), b"12345");
    assert_eq!(read_all(&*s, "1000-bytes-file"), b"12345".repeat(200));
    assert!(read_all(&*s, "empty-file").is_empty());
    let sp = read_all(&*s, "Sparse-File");
    assert_eq!(sp.len(), 500_005);
    assert_eq!(&sp[..5], b"12345");
    assert!(sp[5..500_000].iter().all(|b| *b == 0));
    assert_eq!(&sp[500_000..], b"11111");
    // The upstream volume has no Windows layout: nothing to collect, and that is not an error.
    assert!(targets::resolve(&*s, &Group::ALL, &[]).is_empty());
    let pkg = tempfile::tempdir().unwrap();
    let o = copy_one(
        &*s,
        &Target {
            group: Group::Prefetch,
            path: "1000-bytes-file".into(),
        },
        pkg.path(),
        &[HashAlgo::Sha256],
        false,
        &mut |_| true,
    );
    let Outcome::Collected(c) = o else {
        panic!("{:?}", o)
    };
    assert_eq!(c.method, ReadMethod::Raw);
    assert_eq!(c.bytes, 1000);
    assert_eq!(
        c.digests[0].1,
        crate::hash::hash_bytes(&b"12345".repeat(200), HashAlgo::Sha256)
    );
    assert_eq!(c.before.as_ref().unwrap().size, 1000);
    assert!(c.before.as_ref().unwrap().mft_record.is_some());
}

#[test]
fn mbr_disk_images_use_the_first_ntfs_partition() {
    let vol = fixture("ntfs-testfs1.img.gz");
    let mut disk = vec![0u8; 2048 * 512];
    let e = &mut disk[446..462];
    e[4] = 0x0C; // a FAT32 entry first: skipped
    let e = &mut disk[462..478];
    e[4] = 0x07;
    e[8..12].copy_from_slice(&2048u32.to_le_bytes());
    e[12..16].copy_from_slice(&((vol.len() / 512) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk.extend_from_slice(&vol);
    let (_d, p) = image_file("disk.img", &disk);
    let s = open_image(&p).unwrap();
    assert_eq!(s.describe()["layout"], "mbr");
    assert_eq!(s.describe()["partition_offset"], 2048 * 512);
    assert_eq!(read_all(&*s, "file-with-12345"), b"12345");

    // GPT (protective MBR) is refused with a clear message.
    disk[446 + 4] = 0xEE;
    let (_d2, p2) = image_file("gpt.img", &disk);
    let e = open_image(&p2).err().unwrap();
    assert!(e.contains("GPT"), "{}", e);
}

#[test]
fn non_ntfs_files_are_refused() {
    let (_d, p) = image_file("x.bin", &[0u8; 4096]);
    let e = open_image(&p).err().unwrap();
    assert!(e.contains("not an NTFS volume image"), "{}", e);
    let (_d2, p2) = image_file("y.bin", b"tiny");
    assert!(open_image(&p2).is_err());
    assert!(open_image(Path::new("does/not/exist.dd")).is_err());
}

/// A device that only accepts 512-byte aligned reads (a volume handle), holding the fixture.
struct Device(Cursor<Vec<u8>>);

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.0.position().is_multiple_of(512) || !buf.len().is_multiple_of(512) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unaligned read",
            ));
        }
        self.0.read(buf)
    }
}

impl Seek for Device {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

#[test]
fn raw_device_path_reads_with_aligned_io_only() {
    let mut img = fixture("ntfs-windows.img.gz");
    // A device that ends mid-block (but on a sector boundary): the last block is shortened.
    img.truncate(img.len() - 512 * 3);
    let vol = open_raw_device(Device(Cursor::new(img)), "fake").unwrap();
    let mut b = vec![];
    vol.open("Windows/System32/config/SYSTEM")
        .unwrap()
        .read_to_end(&mut b)
        .unwrap();
    assert_eq!(&b[..4], b"regf");
    assert_eq!(b.len(), 12 * 1024);
    assert_eq!(vol.list("Windows/Prefetch").unwrap().len(), 41);
    let e = open_raw_device(Device(Cursor::new(vec![0u8; 8192])), "blank")
        .err()
        .unwrap();
    assert!(e.contains("not an NTFS volume"), "{}", e);
}

#[test]
fn nt_times_keep_the_100ns_resolution() {
    assert_eq!(
        volume::nt_time(ntfs::NtfsTime::from(0u64)).as_deref(),
        Some("1601-01-01T00:00:00.0000000Z")
    );
    // 2026-01-02T03:04:05.9999999Z: the full 100-ns NTFS resolution is kept (change detection).
    let t = (1_767_323_045u64 + 11_644_473_600) * 10_000_000 + 9_999_999;
    assert_eq!(
        volume::nt_time(ntfs::NtfsTime::from(t)).as_deref(),
        Some("2026-01-02T03:04:05.9999999Z")
    );
}

#[test]
fn live_source_without_admin_uses_the_file_api() {
    let r = open_live(false);
    if cfg!(windows) {
        let s = r.unwrap();
        assert_eq!(s.kind(), "live");
        assert_eq!(s.method(), ReadMethod::Api);
        assert_eq!(s.describe()["method"], "api");
        assert!(s.describe().get("raw_error").is_none());
    } else {
        assert!(r.is_err());
    }
}
