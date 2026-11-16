//! Live triage collection: the frozen data model shared by the sources, the copy step, the volatile capture and
//! the pipeline (`run.rs`). Field and variant names here are FROZEN for v0.1: add, never rename.
//!
//! ```text
//! preflight (elevation, output volume, host facts)
//!   ──► volatile capture (live source only) ──► volatile/*.json
//!   ──► targets per group (hives, evtx, prefetch, browsers, tasks)
//!   ──► copy each target: stat ─► stream + hash (one read) ─► stat again ─► package/artifacts/<group>/<path>
//!   ──► manifest.json + manifest.csv
//! the pipeline then re-reads every packaged file and compares it with the digests taken during the copy
//! ```
//!
//! Paths inside a source are *volume paths*: relative to the volume root, `/`-separated, no drive letter
//! (`Windows/System32/config/SYSTEM`). Matching is case-insensitive, as on NTFS.

pub mod copy;
pub mod host;
pub mod ntfs_source;
pub mod phase;
pub mod source;
pub mod targets;
pub mod volatile;

use crate::analyzer::{Finding, Severity};
use serde::Serialize;
use std::path::PathBuf;

pub use source::{DirEntry, Opened, Source};

/// Artifact groups. `volatile` is captured from the running system; the others are files copied from the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    Volatile,
    Evtx,
    Hives,
    Prefetch,
    Browsers,
    Tasks,
}

impl Group {
    pub const ALL: [Group; 6] = [
        Group::Volatile,
        Group::Evtx,
        Group::Hives,
        Group::Prefetch,
        Group::Browsers,
        Group::Tasks,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Group::Volatile => "volatile",
            Group::Evtx => "evtx",
            Group::Hives => "hives",
            Group::Prefetch => "prefetch",
            Group::Browsers => "browsers",
            Group::Tasks => "tasks",
        }
    }

    pub fn parse(s: &str) -> Option<Group> {
        Group::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(s.trim()))
    }

    /// `"volatile,evtx"` → groups (sorted, de-duplicated); `"all"` → every group.
    pub fn parse_list(s: &str) -> Result<Vec<Group>, String> {
        let mut out = vec![];
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if part.eq_ignore_ascii_case("all") {
                out.extend(Group::ALL);
                continue;
            }
            out.push(Group::parse(part).ok_or_else(|| {
                format!(
                    "unknown group '{}': use {} or all",
                    part,
                    Group::ALL.map(|g| g.name()).join(", ")
                )
            })?);
        }
        out.sort();
        out.dedup();
        if out.is_empty() {
            return Err("select at least one group".into());
        }
        Ok(out)
    }
}

/// Where the artifacts are read from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "lowercase")]
pub enum SourceSpec {
    /// The running Windows system: raw NTFS read of the system volume when elevated, the file API otherwise.
    Live,
    /// A raw NTFS volume image (`.dd`, `.img`, `.raw`): rehearsal and tests.
    Image(PathBuf),
    /// A folder laid out like a Windows volume root (a mounted image or a test fixture).
    Directory(PathBuf),
}

impl SourceSpec {
    /// `live`, or a path: a regular file is an image, a folder is a directory source.
    pub fn parse(s: &str) -> SourceSpec {
        if s.eq_ignore_ascii_case("live") {
            return SourceSpec::Live;
        }
        let p = PathBuf::from(s);
        if p.is_dir() {
            SourceSpec::Directory(p)
        } else {
            SourceSpec::Image(p)
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            SourceSpec::Live => "live",
            SourceSpec::Image(_) => "image",
            SourceSpec::Directory(_) => "directory",
        }
    }
}

/// Domain options (the CLI flags and GUI settings map 1:1 onto these fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CollectOptions {
    pub source: SourceSpec,
    pub groups: Vec<Group>,
    /// Only these user profiles (folder names under `Users/`); empty = every profile.
    pub users: Vec<String>,
    /// Allow writing the package on the system volume of the machine being collected (refused otherwise).
    pub allow_same_volume: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            source: SourceSpec::Live,
            groups: Group::ALL.to_vec(),
            users: vec![],
            allow_same_volume: false,
        }
    }
}

/// How the bytes were read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadMethod {
    /// Parsed from the raw NTFS volume (live volume handle or image file): locked files are readable.
    Raw,
    /// Normal file API (`CreateFile` / `std::fs`): locked files fail.
    Api,
    /// Captured from the running system (volatile JSON written by this tool).
    Snapshot,
}

impl ReadMethod {
    pub fn name(&self) -> &'static str {
        match self {
            ReadMethod::Raw => "raw",
            ReadMethod::Api => "api",
            ReadMethod::Snapshot => "snapshot",
        }
    }
}

/// File-system metadata of one source file. Times are UTC RFC 3339 strings (`2026-11-15T10:00:00Z`), `None`
/// when the source does not expose them. `si_*` = `$STANDARD_INFORMATION` (what Explorer shows), `fn_*` =
/// `$FILE_NAME` (raw NTFS only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FileMeta {
    pub size: u64,
    pub mft_record: Option<u64>,
    pub si_created: Option<String>,
    pub si_modified: Option<String>,
    pub si_mft_changed: Option<String>,
    pub si_accessed: Option<String>,
    pub fn_created: Option<String>,
    pub fn_modified: Option<String>,
    pub fn_mft_changed: Option<String>,
    pub fn_accessed: Option<String>,
    pub sparse: bool,
    pub compressed: bool,
    pub encrypted: bool,
}

impl FileMeta {
    /// What may legitimately differ between the stat before and after a copy of an unchanged file: nothing
    /// that describes content (size, modified, MFT change). Access time is ignored (reading can update it).
    pub fn changed_fields(&self, after: &FileMeta) -> Vec<&'static str> {
        let mut v = vec![];
        if self.size != after.size {
            v.push("size");
        }
        if self.si_modified != after.si_modified {
            v.push("si_modified");
        }
        if self.si_mft_changed != after.si_mft_changed {
            v.push("si_mft_changed");
        }
        if self.mft_record != after.mft_record {
            v.push("mft_record");
        }
        v
    }
}

/// One file to collect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    pub group: Group,
    /// Volume path (`Windows/Prefetch/CMD.EXE-0BD30981.pf`).
    pub path: String,
}

/// A target list entry: a file to copy, or a folder that could not be listed (its files are not collected).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    File(Target),
    Unlisted {
        group: Group,
        path: String,
        error: std::io::ErrorKind,
        message: String,
        raw_os_error: Option<i32>,
    },
}

/// A packaged file: a copied artifact or a volatile snapshot file.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Collected {
    pub group: Group,
    /// Volume path of the source (artifacts) or `volatile/<name>` (snapshots).
    pub source_path: String,
    /// How a reader of the report names the source (`C:\Windows\...`, `image.dd:\Windows\...`).
    pub source_display: String,
    /// Path inside the package, `/`-separated (`artifacts/hives/Windows/System32/config/SYSTEM`).
    pub package_rel: String,
    pub package_path: PathBuf,
    pub method: ReadMethod,
    pub before: Option<FileMeta>,
    pub after: Option<FileMeta>,
    /// Bytes read from the source (= bytes written to the package).
    pub bytes: u64,
    /// Digests of the bytes read, taken during the copy (run algorithms, in order).
    pub digests: Vec<(crate::hash::HashAlgo, String)>,
    /// `Some(offset)` when reading stopped early on an error at that offset (`PARTIAL_READ`).
    pub truncated_at: Option<u64>,
    pub read_error: Option<String>,
    pub findings: Vec<Finding>,
}

/// A target that is not in the package, with the reason.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NotCollected {
    pub group: Group,
    pub source_path: String,
    pub source_display: String,
    pub reason: String,
    pub finding: Finding,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Collected(Box<Collected>),
    NotCollected(NotCollected),
    Cancelled,
}

/// Finding codes of this tool (worded in i18n/*.json). Signals about how the copy was made, never verdicts.
pub mod codes {
    pub const COLLECTED_RAW: &str = "COLLECTED_RAW";
    pub const COLLECTED_API: &str = "COLLECTED_API";
    pub const NOT_COLLECTED_NO_ADMIN: &str = "NOT_COLLECTED_NO_ADMIN";
    pub const NOT_COLLECTED_LOCKED: &str = "NOT_COLLECTED_LOCKED";
    pub const NOT_COLLECTED_ERROR: &str = "NOT_COLLECTED_ERROR";
    pub const CHANGED_DURING_COPY: &str = "CHANGED_DURING_COPY";
    pub const PARTIAL_READ: &str = "PARTIAL_READ";
    pub const COPY_REREAD_MISMATCH: &str = "COPY_REREAD_MISMATCH";
    pub const VOLATILE_PARTIAL: &str = "VOLATILE_PARTIAL";
    pub const OUTPUT_ON_SYSTEM_VOLUME: &str = "OUTPUT_ON_SYSTEM_VOLUME";
    pub const NOT_AVAILABLE_FROM_SOURCE: &str = "NOT_AVAILABLE_FROM_SOURCE";
    /// A file the tool generated from the running system (volatile lists, `system.json`), not a copy.
    pub const CAPTURED_SNAPSHOT: &str = "CAPTURED_SNAPSHOT";
}

/// Classifies an open/list error into the not-collected finding (see `codes`).
pub fn not_collected_finding(
    kind: std::io::ErrorKind,
    raw_os_error: Option<i32>,
    message: &str,
    elevated: bool,
    live: bool,
) -> Finding {
    // Windows: 32 ERROR_SHARING_VIOLATION, 33 ERROR_LOCK_VIOLATION, 5 ERROR_ACCESS_DENIED.
    let locked = matches!(raw_os_error, Some(32) | Some(33));
    let denied = kind == std::io::ErrorKind::PermissionDenied || raw_os_error == Some(5);
    if live && !elevated && (locked || denied) {
        Finding::new(codes::NOT_COLLECTED_NO_ADMIN, Severity::Low).with("error", message)
    } else if locked {
        Finding::new(codes::NOT_COLLECTED_LOCKED, Severity::Medium).with("error", message)
    } else {
        Finding::new(codes::NOT_COLLECTED_ERROR, Severity::Medium).with("error", message)
    }
}

/// Opens the source the options name. `elevated` decides raw versus API access for the live system.
pub fn open_source(spec: &SourceSpec, elevated: bool) -> Result<Box<dyn Source>, String> {
    match spec {
        SourceSpec::Directory(p) => Ok(Box::new(source::DirectorySource::open(p)?)),
        SourceSpec::Image(p) => ntfs_source::open_image(p),
        SourceSpec::Live => ntfs_source::open_live(elevated),
    }
}

/// A file-system time as UTC RFC 3339 with 100-ns precision (`2026-11-15T10:00:00.1234567Z`), the resolution
/// NTFS stores: change detection before/after a copy must not miss a write within the same second.
pub fn fs_time(t: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{}.{:07}Z",
        t.format("%Y-%m-%dT%H:%M:%S"),
        t.timestamp_subsec_nanos() / 100
    )
}

/// `C:\Windows\x` style display of a volume path under `prefix` (`C:`, `image.dd:`, a folder).
pub fn display_path(prefix: &str, volume_path: &str) -> String {
    let sep = if prefix.ends_with(':') || prefix.contains('\\') || !prefix.contains('/') {
        '\\'
    } else {
        '/'
    };
    let p: String = volume_path
        .chars()
        .map(|c| if c == '/' { sep } else { c })
        .collect();
    format!("{}{}{}", prefix.trim_end_matches(['\\', '/']), sep, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_parse() {
        assert_eq!(
            Group::parse_list("hives, EVTX,hives").unwrap(),
            vec![Group::Evtx, Group::Hives]
        );
        assert_eq!(Group::parse_list("all").unwrap().len(), 6);
        assert!(Group::parse_list("ram").is_err());
        assert!(Group::parse_list(" , ").is_err());
    }

    #[test]
    fn classification() {
        use std::io::ErrorKind::*;
        let f = not_collected_finding(PermissionDenied, Some(5), "x", false, true);
        assert_eq!(f.code, codes::NOT_COLLECTED_NO_ADMIN);
        let f = not_collected_finding(Other, Some(32), "x", true, true);
        assert_eq!(f.code, codes::NOT_COLLECTED_LOCKED);
        let f = not_collected_finding(PermissionDenied, Some(5), "x", true, true);
        assert_eq!(f.code, codes::NOT_COLLECTED_ERROR);
        let f = not_collected_finding(PermissionDenied, None, "x", false, false);
        assert_eq!(f.code, codes::NOT_COLLECTED_ERROR);
    }

    #[test]
    fn file_system_times_keep_100ns_precision() {
        let t =
            chrono::DateTime::<chrono::Utc>::from_timestamp(1_763_200_000, 123_456_700).unwrap();
        assert_eq!(fs_time(t), "2025-11-15T09:46:40.1234567Z");
        let a = FileMeta {
            si_modified: Some(fs_time(t)),
            ..Default::default()
        };
        let later = t + chrono::Duration::milliseconds(200);
        let b = FileMeta {
            si_modified: Some(fs_time(later)),
            ..Default::default()
        };
        assert_eq!(a.changed_fields(&b), vec!["si_modified"]);
    }

    #[test]
    fn display() {
        assert_eq!(
            display_path("C:", "Windows/System32/config/SYSTEM"),
            "C:\\Windows\\System32\\config\\SYSTEM"
        );
        assert_eq!(display_path("/mnt/img", "Windows/x"), "/mnt/img/Windows/x");
    }
}
