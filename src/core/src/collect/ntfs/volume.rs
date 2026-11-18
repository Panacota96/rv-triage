//! A read-only NTFS volume over any `Read + Seek` (an image file, a partition of a disk image, a live volume
//! handle behind the aligned reader), parsed with the `ntfs` crate.
//!
//! * Paths are looked up through the `$I30` directory indexes, case-insensitively with the volume's `$UpCase`
//!   table. A reparse point (junction, symbolic link, placeholder) is never traversed and is listed as a file,
//!   so a walk can never follow a link.
//! * `open` streams the unnamed `$DATA` stream (resident or not; sparse runs read as zeros; bytes past the
//!   valid data length read as zeros, as Windows returns them). Compressed, encrypted and reparse-point data
//!   are refused with `ErrorKind::Unsupported`: the parser cannot decode them and wrong bytes are never served.
//! * The parser state sits behind a mutex; every reader re-resolves its file record on each read (and checks
//!   its sequence number), so readers only borrow the volume.

use crate::collect::{DirEntry, FileMeta};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileName, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsAttributeFlags, NtfsError, NtfsFile, NtfsReadSeek, NtfsTime};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Mutex, MutexGuard};

/// Records 0..23 are reserved for the NTFS metafiles (`$MFT`, `$LogFile`, `$Extend`...).
const FIRST_USER_RECORD: u64 = 24;
const ROOT_RECORD: u64 = 5;

/// Geometry and identity of the volume, as its boot sector and `$Volume` describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeInfo {
    pub bytes_per_sector: u16,
    pub cluster_size: u32,
    pub file_record_size: u32,
    pub serial: u64,
    pub size: u64,
    pub ntfs_version: Option<String>,
    pub label: Option<String>,
}

impl VolumeInfo {
    /// `ABCD-1234`: the low 32 bits, as `vol` and `dir` show the serial.
    pub fn serial_short(&self) -> String {
        let s = self.serial as u32;
        format!("{:04X}-{:04X}", s >> 16, s & 0xFFFF)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "bytes_per_sector": self.bytes_per_sector,
            "cluster_size": self.cluster_size,
            "file_record_size": self.file_record_size,
            "volume_serial": self.serial_short(),
            "volume_serial_64": format!("{:016X}", self.serial),
            "total_size": self.size,
            "ntfs_version": self.ntfs_version,
            "volume_label": self.label,
        })
    }
}

struct State<R> {
    fs: R,
    ntfs: Ntfs,
}

pub struct NtfsVolume<R> {
    state: Mutex<State<R>>,
    info: VolumeInfo,
}

fn err(e: NtfsError) -> io::Error {
    io::Error::from(e)
}

fn not_found(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{}: not found on the NTFS volume", path),
    )
}

fn unsupported(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{}: {} (raw NTFS read not supported)", path, why),
    )
}

/// UTC RFC 3339 with the full 100-ns NTFS resolution (`crate::collect::fs_time`).
pub fn nt_time(t: NtfsTime) -> Option<String> {
    let ts = t.nt_timestamp();
    let secs = (ts / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ts % 10_000_000) * 100) as u32;
    crate::collect::fs_time(secs, nanos)
}

/// Runs a parser call, turning a panic in the parser (corrupt or changing metadata) into an error instead of
/// aborting the collection.
fn guarded<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the NTFS parser failed on inconsistent metadata",
        ))
    })
}

fn is_reparse(file: &NtfsFile) -> io::Result<bool> {
    Ok(file
        .info()
        .map_err(err)?
        .file_attributes()
        .contains(NtfsFileAttributeFlags::REPARSE_POINT))
}

/// The preferred `$FILE_NAME` of a file (the long name, not the 8.3 alias).
fn long_name<R: Read + Seek>(file: &NtfsFile, fs: &mut R) -> Option<NtfsFileName> {
    for ns in [
        NtfsFileNamespace::Win32,
        NtfsFileNamespace::Win32AndDos,
        NtfsFileNamespace::Posix,
    ] {
        if let Some(Ok(n)) = file.name(fs, Some(ns), None) {
            return Some(n);
        }
    }
    file.name(fs, None, None).and_then(|r| r.ok())
}

fn parts(path: &str) -> io::Result<Vec<&str>> {
    let v: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if v.iter()
        .any(|p| *p == "." || *p == ".." || p.contains(['\\', ':']))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe volume path {}", path),
        ));
    }
    Ok(v)
}

/// What a reader needs to stream one `$DATA` stream.
struct DataPlan {
    record: u64,
    sequence: u16,
    len: u64,
    valid_len: u64,
}

impl<R: Read + Seek> NtfsVolume<R> {
    /// Parses the boot sector and the `$UpCase` table. The reader must start at the volume's first byte.
    pub fn new(mut fs: R) -> io::Result<NtfsVolume<R>> {
        guarded(move || {
            let mut ntfs = Ntfs::new(&mut fs).map_err(err)?;
            ntfs.read_upcase_table(&mut fs).map_err(err)?;
            let ntfs_version = ntfs
                .volume_info(&mut fs)
                .ok()
                .map(|v| format!("{}.{}", v.major_version(), v.minor_version()));
            let label = ntfs
                .volume_name(&mut fs)
                .and_then(|r| r.ok())
                .map(|n| n.name().to_string_lossy());
            let info = VolumeInfo {
                bytes_per_sector: ntfs.sector_size(),
                cluster_size: ntfs.cluster_size(),
                file_record_size: ntfs.file_record_size(),
                serial: ntfs.serial_number(),
                size: ntfs.size(),
                ntfs_version,
                label,
            };
            Ok(NtfsVolume {
                state: Mutex::new(State { fs, ntfs }),
                info,
            })
        })
    }

    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }

    fn lock(&self) -> MutexGuard<'_, State<R>> {
        // A panic caught by `guarded` may poison the lock; every call seeks before reading, so the state
        // is still usable.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Resolves a volume path to its file record, never through a reparse point.
    fn lookup<'n>(ntfs: &'n Ntfs, fs: &mut R, path: &str) -> io::Result<NtfsFile<'n>> {
        let mut cur = ntfs.root_directory(fs).map_err(err)?;
        for part in parts(path)? {
            if !cur.is_directory() || (cur.file_record_number() != ROOT_RECORD && is_reparse(&cur)?)
            {
                return Err(not_found(path));
            }
            let next = {
                let index = cur.directory_index(fs).map_err(err)?;
                let mut finder = index.finder();
                let entry = NtfsFileNameIndex::find(&mut finder, ntfs, fs, part)
                    .ok_or_else(|| not_found(path))?
                    .map_err(err)?;
                entry.to_file(ntfs, fs).map_err(err)?
            };
            cur = next;
        }
        Ok(cur)
    }

    pub fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>> {
        guarded(|| {
            let mut st = self.lock();
            let State { fs, ntfs } = &mut *st;
            let d = Self::lookup(ntfs, fs, dir)?;
            if !d.is_directory() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{}: not a folder", dir),
                ));
            }
            if d.file_record_number() != ROOT_RECORD && is_reparse(&d)? {
                return Err(unsupported(dir, "reparse point (link), not followed"));
            }
            let at_root = d.file_record_number() == ROOT_RECORD;
            let index = d.directory_index(fs).map_err(err)?;
            let mut entries = index.entries();
            let mut found: Vec<(String, u64, bool)> = vec![];
            while let Some(e) = entries.next(fs) {
                let e = e.map_err(err)?;
                let Some(key) = e.key() else { continue };
                let key = key.map_err(err)?;
                if key.namespace() == NtfsFileNamespace::Dos {
                    continue; // the 8.3 alias of a long name listed under its own entry
                }
                let name = key.name().to_string_lossy();
                let record = e.file_reference().file_record_number();
                if name == "." || name == ".." || record == d.file_record_number() {
                    continue;
                }
                if at_root && name.starts_with('$') && record < FIRST_USER_RECORD {
                    continue; // NTFS metafiles ($MFT, $Extend...), not $Recycle.Bin
                }
                let reparse = key
                    .file_attributes()
                    .contains(NtfsFileAttributeFlags::REPARSE_POINT);
                found.push((name, record, key.is_directory() && !reparse));
            }
            drop(entries);
            let mut out = Vec::with_capacity(found.len());
            for (name, record, mut is_dir) in found {
                // The index copy of the attributes can lag behind the file record: check folders there too. A
                // record that cannot be read keeps the index view (one damaged record must not hide a folder).
                if is_dir && let Ok(f) = ntfs.file(fs, record) {
                    is_dir = f.is_directory() && !is_reparse(&f).unwrap_or(false);
                }
                out.push(DirEntry { name, is_dir });
            }
            Ok(out)
        })
    }

    pub fn stat(&self, path: &str) -> io::Result<FileMeta> {
        guarded(|| {
            let mut st = self.lock();
            let State { fs, ntfs } = &mut *st;
            let f = Self::lookup(ntfs, fs, path)?;
            if f.is_directory() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            let si = f.info().map_err(err)?;
            let attrs = si.file_attributes();
            let mut meta = FileMeta {
                mft_record: Some(f.file_record_number()),
                si_created: nt_time(si.creation_time()),
                si_modified: nt_time(si.modification_time()),
                si_mft_changed: nt_time(si.mft_record_modification_time()),
                si_accessed: nt_time(si.access_time()),
                sparse: attrs.contains(NtfsFileAttributeFlags::SPARSE_FILE),
                compressed: attrs.contains(NtfsFileAttributeFlags::COMPRESSED),
                encrypted: attrs.contains(NtfsFileAttributeFlags::ENCRYPTED),
                ..FileMeta::default()
            };
            if let Some(n) = long_name(&f, fs) {
                meta.fn_created = nt_time(n.creation_time());
                meta.fn_modified = nt_time(n.modification_time());
                meta.fn_mft_changed = nt_time(n.mft_record_modification_time());
                meta.fn_accessed = nt_time(n.access_time());
            }
            if let Some(item) = f.data(fs, "") {
                let item = item.map_err(err)?;
                let a = item.to_attribute().map_err(err)?;
                let fl = a.flags();
                meta.size = a.value_length();
                meta.sparse |= fl.contains(NtfsAttributeFlags::SPARSE);
                meta.compressed |= fl.contains(NtfsAttributeFlags::COMPRESSED);
                meta.encrypted |= fl.contains(NtfsAttributeFlags::ENCRYPTED);
            }
            Ok(meta)
        })
    }

    fn plan(&self, path: &str) -> io::Result<DataPlan> {
        guarded(|| {
            let mut st = self.lock();
            let State { fs, ntfs } = &mut *st;
            let f = Self::lookup(ntfs, fs, path)?;
            if f.is_directory() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            let attrs = f.info().map_err(err)?.file_attributes();
            if attrs.contains(NtfsFileAttributeFlags::REPARSE_POINT) {
                return Err(unsupported(
                    path,
                    "reparse point (link, placeholder or system-compressed file)",
                ));
            }
            if attrs.contains(NtfsFileAttributeFlags::ENCRYPTED) {
                return Err(unsupported(path, "EFS-encrypted data"));
            }
            let record = f.file_record_number();
            let sequence = f.sequence_number();
            let Some(item) = f.data(fs, "") else {
                return Ok(DataPlan {
                    record,
                    sequence,
                    len: 0,
                    valid_len: 0,
                });
            };
            let item = item.map_err(err)?;
            let a = item.to_attribute().map_err(err)?;
            let fl = a.flags();
            if fl.contains(NtfsAttributeFlags::ENCRYPTED) {
                return Err(unsupported(path, "EFS-encrypted data"));
            }
            if fl.contains(NtfsAttributeFlags::COMPRESSED)
                || attrs.contains(NtfsFileAttributeFlags::COMPRESSED)
            {
                return Err(unsupported(path, "NTFS-compressed (LZNT1) data"));
            }
            let len = a.value_length();
            let valid_len = if a.is_resident() {
                len
            } else {
                let rec = (
                    f.position().value().map(|p| p.get()),
                    ntfs.file_record_size(),
                );
                let at = a.position().value().map(|p| p.get());
                match (rec, at) {
                    ((Some(rec_pos), rec_size), Some(attr_pos)) => {
                        initialized_size(fs, rec_pos, rec_size, attr_pos, len)?.unwrap_or(len)
                    }
                    _ => len,
                }
            };
            Ok(DataPlan {
                record,
                sequence,
                len,
                valid_len: valid_len.min(len),
            })
        })
    }

    pub fn open(&self, path: &str) -> io::Result<NtfsReader<'_, R>> {
        let plan = self.plan(path)?;
        Ok(NtfsReader {
            vol: self,
            path: path.to_string(),
            plan,
            pos: 0,
        })
    }
}

/// Reads the initialized (valid data) size from a non-resident attribute header on disk: it is not exposed by
/// the parser. `None` when it cannot be read safely (then the full size is used, as the parser does).
fn initialized_size<R: Read + Seek>(
    fs: &mut R,
    rec_pos: u64,
    rec_size: u32,
    attr_pos: u64,
    data_size: u64,
) -> io::Result<Option<u64>> {
    // Non-resident header: 0x10 starting VCN, 0x30 data size, 0x38 initialized size.
    let mut hdr = [0u8; 0x40];
    fs.seek(SeekFrom::Start(attr_pos))?;
    fs.read_exact(&mut hdr)?;
    // The last two bytes of every 512-byte stride of an MFT record hold the update sequence number on disk;
    // the real values sit in the record's update sequence array.
    let stride_hits: Vec<usize> = (0..hdr.len())
        .filter(|i| (attr_pos + *i as u64) % 512 >= 510)
        .collect();
    if !stride_hits.is_empty() {
        if attr_pos < rec_pos || attr_pos + 0x40 > rec_pos + rec_size as u64 {
            return Ok(None); // attribute in an extension record: not worth the risk
        }
        let mut rec = vec![0u8; rec_size as usize];
        fs.seek(SeekFrom::Start(rec_pos))?;
        fs.read_exact(&mut rec)?;
        let usa_off = u16::from_le_bytes([rec[4], rec[5]]) as usize;
        let usa_cnt = u16::from_le_bytes([rec[6], rec[7]]) as usize;
        for i in stride_hits {
            let in_rec = (attr_pos - rec_pos) as usize + i;
            let stride = in_rec / 512;
            let at = usa_off + 2 * (stride + 1) + (in_rec % 2);
            if stride + 1 >= usa_cnt || at >= rec.len() {
                return Ok(None);
            }
            hdr[i] = rec[at];
        }
    }
    let u64_at = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap_or([0; 8]));
    if u64_at(0x10) != 0 || u64_at(0x30) != data_size {
        return Ok(None); // not the first extent, or not the header we think: do not guess
    }
    Ok(Some(u64_at(0x38)))
}

/// Streams one file's unnamed `$DATA` stream from the volume.
pub struct NtfsReader<'a, R> {
    vol: &'a NtfsVolume<R>,
    path: String,
    plan: DataPlan,
    pos: u64,
}

impl<R: Read + Seek> NtfsReader<'_, R> {
    pub fn len(&self) -> u64 {
        self.plan.len
    }

    pub fn is_empty(&self) -> bool {
        self.plan.len == 0
    }
}

impl<R: Read + Seek> Read for NtfsReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let p = &self.plan;
        if buf.is_empty() || self.pos >= p.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(p.len - self.pos) as usize;
        if self.pos >= p.valid_len {
            buf[..want].fill(0);
            self.pos += want as u64;
            return Ok(want);
        }
        let want = (want as u64).min(p.valid_len - self.pos) as usize;
        let (record, sequence, pos, path) = (p.record, p.sequence, self.pos, &self.path);
        let n = guarded(|| {
            let mut st = self.vol.lock();
            let State { fs, ntfs } = &mut *st;
            let f = ntfs.file(fs, record).map_err(err)?;
            if f.sequence_number() != sequence {
                return Err(io::Error::other(format!(
                    "{}: MFT record {} was reused while it was being read",
                    path, record
                )));
            }
            let item = f
                .data(fs, "")
                .ok_or_else(|| io::Error::other(format!("{}: data stream vanished", path)))?
                .map_err(err)?;
            let a = item.to_attribute().map_err(err)?;
            let mut v = a.value(fs).map_err(err)?;
            v.seek(fs, SeekFrom::Start(pos)).map_err(err)?;
            let mut done = 0;
            while done < want {
                match v.read(fs, &mut buf[done..want]).map_err(err)? {
                    0 => break,
                    n => done += n,
                }
            }
            Ok(done)
        })?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{}: data ends before its recorded size", self.path),
            ));
        }
        self.pos += n as u64;
        Ok(n)
    }
}
