//! The source trait (FROZEN for v0.1) and the directory source.
//!
//! A source is read-only: no implementation may open anything for writing, create files or change
//! timestamps on the machine being collected. Volume paths are `/`-separated and relative to the volume root.

use super::{FileMeta, ReadMethod};
use serde_json::{Value, json};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The name as stored on the volume (original case).
    pub name: String,
    pub is_dir: bool,
}

/// An open source file and how it is being read.
pub struct Opened<'a> {
    pub reader: Box<dyn Read + 'a>,
    pub method: ReadMethod,
}

pub trait Source {
    /// `live`, `image` or `directory` (matches `SourceSpec::kind`).
    fn kind(&self) -> &'static str;
    /// The read method used when nothing fails (`raw` for an elevated live source or an image).
    fn method(&self) -> ReadMethod;
    /// What the audit log and the reports record about the source (volume, serial, sizes, method...).
    fn describe(&self) -> Value;
    /// Prefix for display paths: `C:`, `evidence.dd:`, or the folder.
    fn display_prefix(&self) -> String;
    /// Entries of a folder (volume path; `""` = root). Names keep their case; order is not significant.
    fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>>;
    /// Metadata of one file.
    fn stat(&self, path: &str) -> io::Result<FileMeta>;
    /// Opens one file for reading (data stream only; alternate data streams are out of scope in v0.1).
    fn open(&self, path: &str) -> io::Result<Opened<'_>>;
}

/// A folder laid out like a Windows volume root. Read with the normal file API (`std::fs`, read-only).
pub struct DirectorySource {
    root: PathBuf,
}

impl DirectorySource {
    pub fn open(root: &Path) -> Result<DirectorySource, String> {
        if !root.is_dir() {
            return Err(format!("source {} is not a folder", root.display()));
        }
        Ok(DirectorySource {
            root: std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf()),
        })
    }

    fn full(&self, path: &str) -> io::Result<PathBuf> {
        let mut p = self.root.clone();
        for part in path.split('/').filter(|s| !s.is_empty()) {
            if part == "." || part == ".." || part.contains(['\\', ':']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsafe volume path {}", path),
                ));
            }
            p.push(part);
        }
        Ok(p)
    }
}

pub(crate) fn utc(t: io::Result<std::time::SystemTime>) -> Option<String> {
    t.ok().map(|t| super::fs_time(t.into()))
}

impl Source for DirectorySource {
    fn kind(&self) -> &'static str {
        "directory"
    }
    fn method(&self) -> ReadMethod {
        ReadMethod::Api
    }
    fn describe(&self) -> Value {
        json!({"kind": "directory", "root": self.root.display().to_string(), "method": "api"})
    }
    fn display_prefix(&self) -> String {
        self.root.display().to_string()
    }
    fn list(&self, dir: &str) -> io::Result<Vec<DirEntry>> {
        let mut out = vec![];
        for e in std::fs::read_dir(self.full(dir)?)? {
            let e = e?;
            let ft = e.file_type()?;
            if ft.is_symlink() {
                continue; // never followed: a link could lead outside the source
            }
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: ft.is_dir(),
            });
        }
        Ok(out)
    }
    fn stat(&self, path: &str) -> io::Result<FileMeta> {
        let m = std::fs::symlink_metadata(self.full(path)?)?;
        if !m.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(FileMeta {
            size: m.len(),
            si_created: utc(m.created()),
            si_modified: utc(m.modified()),
            si_accessed: utc(m.accessed()),
            ..FileMeta::default()
        })
    }
    fn open(&self, path: &str) -> io::Result<Opened<'_>> {
        Ok(Opened {
            reader: Box::new(std::fs::File::open(self.full(path)?)?),
            method: ReadMethod::Api,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_stats_opens_and_refuses_escape() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("Windows/Prefetch")).unwrap();
        std::fs::write(d.path().join("Windows/Prefetch/A.pf"), b"abc").unwrap();
        let s = DirectorySource::open(d.path()).unwrap();
        let l = s.list("Windows").unwrap();
        assert_eq!(
            l,
            vec![DirEntry {
                name: "Prefetch".into(),
                is_dir: true
            }]
        );
        assert_eq!(s.stat("Windows/Prefetch/A.pf").unwrap().size, 3);
        let mut b = vec![];
        s.open("Windows/Prefetch/A.pf")
            .unwrap()
            .reader
            .read_to_end(&mut b)
            .unwrap();
        assert_eq!(b, b"abc");
        assert!(s.open("../x").is_err());
        assert!(s.stat("Windows").is_err());
    }
}
