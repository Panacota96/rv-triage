//! Copies one target into the package: stat → stream + hash in one read → flush → stat again.
//!
//! The digests are taken from the bytes as they are read from the source, before they reach the package, so
//! the pipeline's later re-read of the packaged copy (`COPY_REREAD_MISMATCH`) checks the write path too.
//! A read error mid-file keeps the bytes read so far (`PARTIAL_READ`, with the offset); a write error to the
//! package removes the incomplete copy and reports the target as not collected.

use super::{
    Collected, NotCollected, Outcome, ReadMethod, Source, Target, codes, not_collected_finding,
};
use crate::analyzer::{Finding, Severity};
use crate::hash::{HashAlgo, hash_reader};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Reads from the source and writes every byte read to the package file.
struct Tee<'a, W: Write> {
    inner: Box<dyn Read + 'a>,
    out: W,
    read: u64,
    read_error: Option<io::Error>,
    write_error: Option<io::Error>,
}

impl<W: Write> Read for Tee<'_, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = loop {
            match self.inner.read(buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    // Keep what was read; the hash covers exactly the bytes in the package.
                    self.read_error = Some(e);
                    return Ok(0);
                }
            }
        };
        if let Err(e) = self.out.write_all(&buf[..n]) {
            let msg = e.to_string();
            self.write_error = Some(e);
            return Err(io::Error::other(msg));
        }
        self.read += n as u64;
        Ok(n)
    }
}

/// `artifacts/<group>/<volume path>`; `None` when a part of the path is not safe to recreate.
pub fn package_rel(target: &Target) -> Option<String> {
    let mut parts = vec!["artifacts".to_string(), target.group.name().to_string()];
    for p in target.path.split('/').filter(|s| !s.is_empty()) {
        if p == "." || p == ".." || p.contains(['\\', ':']) || p.chars().any(|c| c.is_control()) {
            return None;
        }
        parts.push(p.to_string());
    }
    Some(parts.join("/"))
}

pub fn package_path(package_dir: &Path, rel: &str) -> PathBuf {
    let mut p = package_dir.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    p
}

fn not_collected(src: &dyn Source, t: &Target, reason: String, finding: Finding) -> Outcome {
    Outcome::NotCollected(NotCollected {
        group: t.group,
        source_path: t.path.clone(),
        source_display: super::display_path(&src.display_prefix(), &t.path),
        reason,
        finding,
    })
}

/// Copies `target` from `src` into `package_dir`. `on_chunk(bytes_so_far) == false` cancels (the incomplete
/// copy is removed). `elevated` only refines why a live target could not be opened.
pub fn copy_one(
    src: &dyn Source,
    target: &Target,
    package_dir: &Path,
    algos: &[HashAlgo],
    elevated: bool,
    on_chunk: &mut dyn FnMut(u64) -> bool,
) -> Outcome {
    let live = src.kind() == "live";
    let classify = |e: &io::Error| {
        not_collected_finding(e.kind(), e.raw_os_error(), &e.to_string(), elevated, live)
    };
    let Some(rel) = package_rel(target) else {
        let msg = "the path cannot be recreated safely in the package".to_string();
        return not_collected(
            src,
            target,
            msg.clone(),
            Finding::new(codes::NOT_COLLECTED_ERROR, Severity::Medium).with("error", msg),
        );
    };
    let before = match src.stat(&target.path) {
        Ok(m) => m,
        Err(e) => return not_collected(src, target, format!("stat: {}", e), classify(&e)),
    };
    let opened = match src.open(&target.path) {
        Ok(o) => o,
        Err(e) => return not_collected(src, target, format!("open: {}", e), classify(&e)),
    };
    let dest = package_path(package_dir, &rel);
    let created = dest
        .parent()
        .map(std::fs::create_dir_all)
        .unwrap_or(Ok(()))
        .and_then(|_| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
        });
    let file = match created {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("cannot create {} in the package: {}", rel, e);
            return not_collected(
                src,
                target,
                msg.clone(),
                Finding::new(codes::NOT_COLLECTED_ERROR, Severity::Medium).with("error", msg),
            );
        }
    };
    let method = opened.method;
    let mut tee = Tee {
        inner: opened.reader,
        out: io::BufWriter::with_capacity(1 << 20, file),
        read: 0,
        read_error: None,
        write_error: None,
    };
    let hashed = hash_reader(&mut tee, algos, on_chunk);
    let Tee {
        out,
        read,
        read_error,
        write_error,
        ..
    } = tee;
    let flushed = out
        .into_inner()
        .map_err(|e| e.into_error())
        .and_then(|f| f.sync_all());
    let fail = |msg: String| {
        let _ = std::fs::remove_file(&dest);
        not_collected(
            src,
            target,
            msg.clone(),
            Finding::new(codes::NOT_COLLECTED_ERROR, Severity::Medium).with("error", msg),
        )
    };
    let out = match hashed {
        Ok(Some(o)) => o,
        Ok(None) => {
            let _ = std::fs::remove_file(&dest);
            return Outcome::Cancelled;
        }
        Err(e) => {
            let e = write_error.map(|w| w.to_string()).unwrap_or(e.to_string());
            return fail(format!("cannot write the package copy: {}", e));
        }
    };
    if let Err(e) = flushed {
        return fail(format!("cannot write the package copy: {}", e));
    }
    let after = src.stat(&target.path).ok();
    let mut findings = vec![match method {
        ReadMethod::Raw => Finding::new(codes::COLLECTED_RAW, Severity::Info),
        _ => Finding::new(codes::COLLECTED_API, Severity::Info),
    }];
    let truncated_at = read_error.as_ref().map(|_| read);
    if let Some(e) = &read_error {
        findings.push(
            Finding::new(codes::PARTIAL_READ, Severity::High)
                .with("offset", read.to_string())
                .with("size", before.size.to_string())
                .with("error", e.to_string()),
        );
    }
    let mut changed: Vec<&str> = after
        .as_ref()
        .map(|a| before.changed_fields(a))
        .unwrap_or_default();
    if read_error.is_none() && read != before.size && !changed.contains(&"size") {
        changed.push("size");
    }
    if !changed.is_empty() {
        findings.push(
            Finding::new(codes::CHANGED_DURING_COPY, Severity::Medium)
                .with("fields", changed.join(", "))
                .with("size_before", before.size.to_string())
                .with("bytes_read", read.to_string()),
        );
    }
    Outcome::Collected(Box::new(Collected {
        group: target.group,
        source_path: target.path.clone(),
        source_display: super::display_path(&src.display_prefix(), &target.path),
        package_rel: rel,
        package_path: dest,
        method,
        before: Some(before),
        after,
        bytes: out.bytes,
        digests: out.digests,
        truncated_at,
        read_error: read_error.map(|e| e.to_string()),
        findings,
    }))
}

/// Writes a volatile snapshot file (`volatile/<name>`) into the package and describes it as collected.
pub fn write_snapshot(
    package_dir: &Path,
    name: &str,
    bytes: &[u8],
    algos: &[HashAlgo],
    findings: Vec<Finding>,
) -> Result<Collected, String> {
    let rel = format!("volatile/{}", name);
    let dest = package_path(package_dir, &rel);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("cannot create {}: {}", p.display(), e))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest)
        .map_err(|e| format!("cannot create {}: {}", dest.display(), e))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {}", dest.display(), e))?;
    let digests = algos
        .iter()
        .map(|&a| (a, crate::hash::hash_bytes(bytes, a)))
        .collect();
    let mut all =
        vec![Finding::new(codes::CAPTURED_SNAPSHOT, Severity::Info).with("file", rel.clone())];
    all.extend(findings);
    Ok(Collected {
        group: super::Group::Volatile,
        source_path: rel.clone(),
        source_display: rel.clone(),
        package_rel: rel,
        package_path: dest,
        method: ReadMethod::Snapshot,
        before: None,
        after: None,
        bytes: bytes.len() as u64,
        digests,
        truncated_at: None,
        read_error: None,
        findings: all,
    })
}

/// A file-like reader that fails after `ok_bytes` (tests of `PARTIAL_READ`).
#[cfg(test)]
pub(crate) struct FailingReader {
    pub data: Vec<u8>,
    pub ok_bytes: usize,
    pub pos: usize,
}

#[cfg(test)]
impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.ok_bytes {
            return Err(io::Error::other("bad sector"));
        }
        let n = buf
            .len()
            .min(self.ok_bytes - self.pos)
            .min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::FileMeta;
    use crate::collect::source::{DirEntry, DirectorySource, Opened};
    use crate::collect::{Group, Outcome};
    use serde_json::Value;

    fn t(group: Group, path: &str) -> Target {
        Target {
            group,
            path: path.into(),
        }
    }

    #[test]
    fn copies_hashes_and_mirrors_the_path() {
        let s = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(s.path().join("Windows/Prefetch")).unwrap();
        std::fs::write(s.path().join("Windows/Prefetch/A.pf"), b"hello").unwrap();
        let pkg = tempfile::tempdir().unwrap();
        let src = DirectorySource::open(s.path()).unwrap();
        let o = copy_one(
            &src,
            &t(Group::Prefetch, "Windows/Prefetch/A.pf"),
            pkg.path(),
            &[HashAlgo::Sha256],
            false,
            &mut |_| true,
        );
        let Outcome::Collected(c) = o else {
            panic!("{:?}", o)
        };
        assert_eq!(c.package_rel, "artifacts/prefetch/Windows/Prefetch/A.pf");
        assert_eq!(std::fs::read(&c.package_path).unwrap(), b"hello");
        assert_eq!(
            c.digests[0].1,
            crate::hash::hash_bytes(b"hello", HashAlgo::Sha256)
        );
        assert_eq!(
            c.findings
                .iter()
                .map(|f| f.code.as_str())
                .collect::<Vec<_>>(),
            vec![codes::COLLECTED_API]
        );
        // a second copy into the same package never overwrites
        let o = copy_one(
            &src,
            &t(Group::Prefetch, "Windows/Prefetch/A.pf"),
            pkg.path(),
            &[HashAlgo::Sha256],
            false,
            &mut |_| true,
        );
        assert!(
            matches!(o, Outcome::NotCollected(n) if n.finding.code == codes::NOT_COLLECTED_ERROR)
        );
        // missing file
        let o = copy_one(
            &src,
            &t(Group::Prefetch, "Windows/Prefetch/B.pf"),
            pkg.path(),
            &[HashAlgo::Sha256],
            false,
            &mut |_| true,
        );
        assert!(matches!(o, Outcome::NotCollected(_)));
        // cancel removes the partial copy
        let o = copy_one(
            &src,
            &t(Group::Evtx, "Windows/Prefetch/A.pf"),
            pkg.path(),
            &[HashAlgo::Sha256],
            false,
            &mut |_| false,
        );
        assert_eq!(o, Outcome::Cancelled);
        assert!(
            !pkg.path()
                .join("artifacts/evtx/Windows/Prefetch/A.pf")
                .exists()
        );
    }

    struct Flaky;
    impl Source for Flaky {
        fn kind(&self) -> &'static str {
            "image"
        }
        fn method(&self) -> ReadMethod {
            ReadMethod::Raw
        }
        fn describe(&self) -> Value {
            Value::Null
        }
        fn display_prefix(&self) -> String {
            "x.dd:".into()
        }
        fn list(&self, _: &str) -> io::Result<Vec<DirEntry>> {
            Ok(vec![])
        }
        fn stat(&self, _: &str) -> io::Result<FileMeta> {
            Ok(FileMeta {
                size: 10,
                ..Default::default()
            })
        }
        fn open(&self, _: &str) -> io::Result<Opened<'_>> {
            Ok(Opened {
                reader: Box::new(FailingReader {
                    data: b"0123456789".to_vec(),
                    ok_bytes: 4,
                    pos: 0,
                }),
                method: ReadMethod::Raw,
            })
        }
    }

    #[test]
    fn a_read_error_keeps_the_bytes_read_and_flags_partial() {
        let pkg = tempfile::tempdir().unwrap();
        let o = copy_one(
            &Flaky,
            &t(Group::Evtx, "Windows/x.evtx"),
            pkg.path(),
            &[HashAlgo::Sha256],
            true,
            &mut |_| true,
        );
        let Outcome::Collected(c) = o else { panic!() };
        assert_eq!(c.truncated_at, Some(4));
        assert_eq!(std::fs::read(&c.package_path).unwrap(), b"0123");
        let codes_: Vec<&str> = c.findings.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes_, vec![codes::COLLECTED_RAW, codes::PARTIAL_READ]);
        assert_eq!(c.source_display, "x.dd:\\Windows\\x.evtx");
    }

    #[test]
    fn unsafe_paths_are_not_recreated() {
        assert!(package_rel(&t(Group::Tasks, "Windows/../x")).is_none());
        assert!(package_rel(&t(Group::Tasks, "Windows/a:b")).is_none());
    }
}
