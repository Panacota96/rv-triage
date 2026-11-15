//! Raw NTFS sources (FROZEN entry points for v0.1): a volume image file, and the live system volume
//! (`\\.\C:` opened read-only when elevated, with the normal file API as fallback for single files; the plain
//! file API only when not elevated).
//!
//! Both parse NTFS with the `ntfs` crate (MIT OR Apache-2.0) through [`NtfsVolume`]. Nothing is ever opened
//! for writing: the image with `File::open`, the live volume with `File::open` on `\\.\C:` (read access, other
//! processes keep read/write/delete sharing), read in whole aligned sectors through [`AlignedReader`].
//!
//! An image may be an NTFS volume image, or a disk image with an MBR partition table whose first NTFS
//! partition is used. GPT disk images are refused in v0.1: extract the NTFS partition into a volume image.

#[path = "ntfs/aligned.rs"]
pub mod aligned;
#[path = "ntfs/volume.rs"]
pub mod volume;

use super::source::{DirectorySource, Source};
use super::{DirEntry, FileMeta, Opened, ReadMethod};
use aligned::{AlignedReader, OffsetReader};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
pub use volume::{NtfsReader, NtfsVolume, VolumeInfo};

/// Reads through the aligned block cache (64 KiB blocks).
const BLOCK: usize = 64 * 1024;
const NTFS_OEM: &[u8; 8] = b"NTFS    ";

fn is_ntfs_boot(sector: &[u8]) -> bool {
    sector.len() >= 11 && &sector[3..11] == NTFS_OEM
}

/// Where the NTFS volume starts inside an image: 0 for a volume image, the first NTFS partition of an MBR.
fn find_volume<R: Read + Seek>(f: &mut R) -> Result<(u64, Option<u64>, &'static str), String> {
    let mut s0 = [0u8; 512];
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    f.read_exact(&mut s0)
        .map_err(|e| format!("cannot read the first sector: {}", e))?;
    if is_ntfs_boot(&s0) {
        return Ok((0, None, "volume"));
    }
    if s0[510..512] != [0x55, 0xAA] {
        return Err(
            "not an NTFS volume image (no NTFS boot sector, no MBR partition table)".into(),
        );
    }
    let entries: Vec<&[u8]> = (0..4).map(|i| &s0[446 + 16 * i..462 + 16 * i]).collect();
    if entries.iter().any(|e| e[4] == 0xEE) {
        return Err("GPT disk images are not supported in v0.1: extract the NTFS partition into a volume image".into());
    }
    for e in entries {
        if e[4] != 0x07 {
            continue;
        }
        let lba = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let sectors = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        let mut b = [0u8; 512];
        if f.seek(SeekFrom::Start(lba * 512)).is_ok()
            && f.read_exact(&mut b).is_ok()
            && is_ntfs_boot(&b)
        {
            return Ok((lba * 512, Some(sectors * 512), "mbr"));
        }
    }
    Err("no NTFS partition in the MBR partition table: v0.1 takes an NTFS volume image or an MBR disk image".into())
}

type ImageReader = AlignedReader<OffsetReader<File>>;

/// A raw NTFS volume image, read-only.
struct ImageSource {
    vol: NtfsVolume<ImageReader>,
    path: PathBuf,
    partition_offset: u64,
    layout: &'static str,
}

/// Opens a raw NTFS volume image (`.dd`, `.img`, `.raw`) read-only.
pub fn open_image(path: &Path) -> Result<Box<dyn Source>, String> {
    let fail = |e: String| format!("{}: {}", path.display(), e);
    let mut f = File::open(path).map_err(|e| fail(e.to_string()))?;
    if f.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(fail("is a folder, not an image file".into()));
    }
    let (offset, len, layout) = find_volume(&mut f).map_err(fail)?;
    let r = AlignedReader::new(OffsetReader::new(f, offset, len), 512, BLOCK);
    let vol = NtfsVolume::new(r).map_err(|e| fail(format!("not a readable NTFS volume: {}", e)))?;
    Ok(Box::new(ImageSource {
        vol,
        path: std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
        partition_offset: offset,
        layout,
    }))
}

fn raw_opened<'a, R: Read + Seek>(r: NtfsReader<'a, R>) -> Opened<'a> {
    Opened {
        reader: Box::new(r),
        method: ReadMethod::Raw,
    }
}

impl Source for ImageSource {
    fn kind(&self) -> &'static str {
        "image"
    }
    fn method(&self) -> ReadMethod {
        ReadMethod::Raw
    }
    fn describe(&self) -> Value {
        let mut v = json!({
            "kind": "image",
            "path": self.path.display().to_string(),
            "method": "raw",
            "layout": self.layout,
            "partition_offset": self.partition_offset,
        });
        if let (Some(o), Value::Object(i)) = (v.as_object_mut(), self.vol.info().to_json()) {
            o.extend(i);
        }
        v
    }
    fn display_prefix(&self) -> String {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string());
        format!("{}:", name)
    }
    fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>> {
        self.vol.list(dir)
    }
    fn stat(&self, path: &str) -> io::Result<FileMeta> {
        self.vol.stat(path)
    }
    fn open(&self, path: &str) -> io::Result<Opened<'_>> {
        self.vol.open(path).map(raw_opened)
    }
}

/// Opens the live system volume. `elevated` = raw read of the volume; otherwise the file API (locked files
/// and other users' profiles are then reported as not collected).
pub fn open_live(elevated: bool) -> Result<Box<dyn Source>, String> {
    #[cfg(not(windows))]
    {
        let _ = elevated;
        Err("live collection needs Windows".into())
    }
    #[cfg(windows)]
    {
        let drive = super::host::system_drive();
        if drive.is_empty() {
            return Err("live collection needs Windows (%SystemDrive% is not set)".into());
        }
        let api = DirectorySource::open(Path::new(&format!("{}\\", drive)))?;
        if !elevated {
            return Ok(Box::new(LiveApi {
                api,
                raw_error: None,
            }));
        }
        match open_raw_volume(&drive) {
            Ok(vol) => Ok(Box::new(LiveRaw { vol, api, drive })),
            Err(e) => Ok(Box::new(LiveApi {
                api,
                raw_error: Some(e),
            })),
        }
    }
}

/// `\\.\C:` read-only, through the aligned reader (4096-byte alignment until the boot sector tells the
/// sector size: a multiple of every common sector size).
#[cfg_attr(not(windows), allow(dead_code))]
fn open_raw_volume(drive: &str) -> Result<NtfsVolume<AlignedReader<File>>, String> {
    let dev = format!(r"\\.\{}", drive);
    let f = File::open(&dev).map_err(|e| format!("{}: {}", dev, e))?;
    open_raw_device(f, &dev)
}

/// Parses an NTFS volume from a device that only accepts aligned reads.
fn open_raw_device<R: Read + Seek>(
    dev: R,
    name: &str,
) -> Result<NtfsVolume<AlignedReader<R>>, String> {
    let mut r = AlignedReader::new(dev, 4096, BLOCK);
    let mut boot = [0u8; 512];
    r.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    r.read_exact(&mut boot)
        .map_err(|e| format!("{}: cannot read the boot sector: {}", name, e))?;
    if !is_ntfs_boot(&boot) {
        return Err(format!("{}: not an NTFS volume", name));
    }
    let bps = u16::from_le_bytes([boot[0x0B], boot[0x0C]]) as u64;
    let total = u64::from_le_bytes(boot[0x28..0x30].try_into().unwrap_or([0; 8]));
    if !bps.is_power_of_two() || !(256..=4096).contains(&bps) {
        return Err(format!("{}: unexpected sector size {}", name, bps));
    }
    r.set_geometry(bps, total.checked_mul(bps));
    NtfsVolume::new(r).map_err(|e| format!("{}: not a readable NTFS volume: {}", name, e))
}

/// The live volume read raw, with the file API as a per-file fallback (a file the parser cannot read, e.g.
/// compressed, or one created since the volume metadata was last flushed).
#[cfg_attr(not(windows), allow(dead_code))]
struct LiveRaw {
    vol: NtfsVolume<AlignedReader<File>>,
    api: DirectorySource,
    drive: String,
}

/// The API error when it carries an OS error code (locked / denied classification), else both messages.
fn both(raw: io::Error, api: io::Error) -> io::Error {
    if api.raw_os_error().is_some() {
        api
    } else {
        io::Error::new(api.kind(), format!("raw: {}; api: {}", raw, api))
    }
}

impl Source for LiveRaw {
    fn kind(&self) -> &'static str {
        "live"
    }
    fn method(&self) -> ReadMethod {
        ReadMethod::Raw
    }
    fn describe(&self) -> Value {
        let mut v = json!({
            "kind": "live",
            "volume": self.drive,
            "device": format!(r"\\.\{}", self.drive),
            "method": "raw",
            "fallback": "api (per file, when the raw read of that file fails)",
        });
        if let (Some(o), Value::Object(i)) = (v.as_object_mut(), self.vol.info().to_json()) {
            o.extend(i);
        }
        v
    }
    fn display_prefix(&self) -> String {
        self.drive.clone()
    }
    fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>> {
        self.vol
            .list(dir)
            .or_else(|raw| self.api.list(dir).map_err(|api| both(raw, api)))
    }
    fn stat(&self, path: &str) -> io::Result<FileMeta> {
        self.vol
            .stat(path)
            .or_else(|raw| self.api.stat(path).map_err(|api| both(raw, api)))
    }
    fn open(&self, path: &str) -> io::Result<Opened<'_>> {
        match self.vol.open(path) {
            Ok(r) => Ok(raw_opened(r)),
            Err(raw) => self.api.open(path).map_err(|api| both(raw, api)),
        }
    }
}

/// The live volume through the file API: a directory source that reports itself as `live`.
#[cfg_attr(not(windows), allow(dead_code))]
struct LiveApi {
    api: DirectorySource,
    /// Why the raw volume could not be opened (elevated runs only).
    raw_error: Option<String>,
}

impl Source for LiveApi {
    fn kind(&self) -> &'static str {
        "live"
    }
    fn method(&self) -> ReadMethod {
        ReadMethod::Api
    }
    fn describe(&self) -> Value {
        let mut v = json!({"kind": "live", "volume": super::host::system_drive(), "method": "api"});
        if let (Some(o), Some(e)) = (v.as_object_mut(), &self.raw_error) {
            o.insert("raw_error".into(), json!(e));
        }
        v
    }
    fn display_prefix(&self) -> String {
        super::host::system_drive()
    }
    fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>> {
        self.api.list(dir)
    }
    fn stat(&self, path: &str) -> io::Result<FileMeta> {
        self.api.stat(path)
    }
    fn open(&self, path: &str) -> io::Result<Opened<'_>> {
        self.api.open(path)
    }
}

#[cfg(test)]
#[path = "ntfs/tests.rs"]
mod tests;
