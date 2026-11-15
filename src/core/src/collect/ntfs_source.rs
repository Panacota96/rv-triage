//! Raw NTFS sources (FROZEN entry points for v0.1): a volume image file, and the live system volume
//! (`\\.\C:` opened read-only when elevated, with the normal file API as fallback for single files; the plain
//! file API only when not elevated).
//!
//! STUB: the NTFS agent implements both with the `ntfs` crate (MIT OR Apache-2.0) over a sector-aligned,
//! read-only reader. Until then the image source fails to open and the live source reads through the file API.

use super::source::{DirectorySource, Source};
use std::path::Path;

/// Opens a raw NTFS volume image (`.dd`, `.img`, `.raw`) read-only.
pub fn open_image(path: &Path) -> Result<Box<dyn Source>, String> {
    Err(format!(
        "{}: NTFS image sources are not implemented yet",
        path.display()
    ))
}

/// Opens the live system volume. `elevated` = raw read of the volume; otherwise the file API (locked files
/// and other users' profiles are then reported as not collected).
pub fn open_live(elevated: bool) -> Result<Box<dyn Source>, String> {
    let _ = elevated;
    let drive = super::host::system_drive();
    if drive.is_empty() {
        return Err("live collection needs Windows (%SystemDrive% is not set)".into());
    }
    Ok(Box::new(LiveApi(DirectorySource::open(Path::new(
        &format!("{}\\", drive),
    ))?)))
}

/// The live volume through the file API: a directory source that reports itself as `live`.
struct LiveApi(DirectorySource);

impl Source for LiveApi {
    fn kind(&self) -> &'static str {
        "live"
    }
    fn method(&self) -> super::ReadMethod {
        super::ReadMethod::Api
    }
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({"kind": "live", "volume": super::host::system_drive(), "method": "api"})
    }
    fn display_prefix(&self) -> String {
        super::host::system_drive()
    }
    fn list(&self, dir: &str) -> std::io::Result<Vec<super::DirEntry>> {
        self.0.list(dir)
    }
    fn stat(&self, path: &str) -> std::io::Result<super::FileMeta> {
        self.0.stat(path)
    }
    fn open(&self, path: &str) -> std::io::Result<super::Opened<'_>> {
        self.0.open(path)
    }
}
