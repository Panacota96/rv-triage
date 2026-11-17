//! The collection phase of a run (called by `run::pipeline` when `RunConfig::collect` is set): preflight,
//! volatile capture, target resolution, copies and the manifest. Every step is in the audit log; every file
//! written to the package is recorded with `output_written` (`details.file` = `package/<rel>`, relative to the
//! run's report folder), so `verify-log` and `tests/verify_chain.py` re-hash it.

use super::{
    CollectOptions, Collected, Group, NotCollected, Outcome, Resolved, SourceSpec, codes, copy,
    host, not_collected_finding, targets, volatile,
};
use crate::analyzer::{Finding, Severity};
use crate::audit::AuditLog;
use crate::events::Event;
use crate::hash::HashAlgo;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// The package folder inside the run's report folder.
pub const PACKAGE_DIR: &str = "package";

#[derive(Debug, Default)]
pub struct PhaseResult {
    pub collected: Vec<Collected>,
    pub not_collected: Vec<NotCollected>,
    /// Audit sequence number of each `artifact_not_collected` entry (same order as `not_collected`).
    pub not_collected_seq: Vec<u64>,
    pub cancelled: bool,
    pub elevated: bool,
}

fn hashes_json(d: &[(HashAlgo, String)]) -> Value {
    Value::Object(
        d.iter()
            .map(|(a, h)| (a.name().to_string(), json!(h)))
            .collect(),
    )
}

fn record_output(log: &mut AuditLog, c: &Collected) -> Result<(), String> {
    log.record(
        "output_written",
        Some(&c.package_rel),
        json!({"file": format!("{}/{}", PACKAGE_DIR, c.package_rel), "kind": format!("package_{}", c.group.name()),
               "bytes": c.bytes, "hashes": hashes_json(&c.digests)}),
    )
    .map(|_| ())
    .map_err(|e| format!("audit log write failed: {}", e))
}

fn record_collected(log: &mut AuditLog, c: &Collected) -> Result<u64, String> {
    let seq = log
        .record(
            "artifact_collected",
            Some(&c.source_display),
            json!({"group": c.group, "source": c.source_path, "package": c.package_rel, "method": c.method,
                   "bytes": c.bytes, "hashes": hashes_json(&c.digests), "before": c.before, "after": c.after,
                   "truncated_at": c.truncated_at, "read_error": c.read_error, "findings": c.findings}),
        )
        .map_err(|e| format!("audit log write failed: {}", e))?;
    record_output(log, c)?;
    Ok(seq)
}

fn record_not_collected(log: &mut AuditLog, n: &NotCollected) -> Result<u64, String> {
    log.record(
        "artifact_not_collected",
        Some(&n.source_display),
        json!({"group": n.group, "source": n.source_path, "reason": n.reason, "finding": n.finding}),
    )
    .map_err(|e| format!("audit log write failed: {}", e))
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// `manifest.csv`: one row per packaged file; `manifest.json`: packaged and not-collected entries.
fn manifests(
    r: &PhaseResult,
    algos: &[HashAlgo],
    source: &Value,
    run_id: &str,
) -> (Vec<u8>, Vec<u8>) {
    let mut csv = format!(
        "package_path,group,source,method,bytes,{},truncated_at,findings\n",
        algos.iter().map(|a| a.name()).collect::<Vec<_>>().join(",")
    );
    for c in &r.collected {
        let h: Vec<String> = algos
            .iter()
            .map(|a| {
                c.digests
                    .iter()
                    .find(|(x, _)| x == a)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            })
            .collect();
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_field(&c.package_rel),
            c.group.name(),
            csv_field(&c.source_display),
            c.method.name(),
            c.bytes,
            h.join(","),
            c.truncated_at.map(|x| x.to_string()).unwrap_or_default(),
            csv_field(
                &c.findings
                    .iter()
                    .map(|f| f.code.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        ));
    }
    let json = json!({
        "format": "rakvor.triage-manifest/1",
        // Which collection this package is: rv-hashinv finds its audit log at <OUT>/logs/<run_id>/audit.jsonl
        // and links the intake to it (also named here for a package copied without that layout).
        "tool": crate::TOOL_NAME,
        "version": crate::TOOL_VERSION,
        "run_id": run_id,
        "collected_utc": crate::time::utc_now(),
        "source": source,
        "algorithms": algos,
        "collected": r.collected.iter().map(|c| json!({
            "package_path": c.package_rel, "group": c.group, "source": c.source_display, "method": c.method,
            "bytes": c.bytes, "hashes": hashes_json(&c.digests), "before": c.before, "after": c.after,
            "truncated_at": c.truncated_at, "findings": c.findings.iter().map(|f| &f.code).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "not_collected": r.not_collected.iter().map(|n| json!({
            "group": n.group, "source": n.source_display, "reason": n.reason, "finding": n.finding.code,
        })).collect::<Vec<_>>(),
    });
    let mut j = serde_json::to_vec_pretty(&json).unwrap_or_default();
    j.push(b'\n');
    (csv.into_bytes(), j)
}

/// Writes a manifest at the package root and records it.
fn write_manifest(
    log: &mut AuditLog,
    package_dir: &Path,
    name: &str,
    bytes: &[u8],
    algos: &[HashAlgo],
) -> Result<(), String> {
    let p = package_dir.join(name);
    std::fs::write(&p, bytes).map_err(|e| format!("cannot write {}: {}", p.display(), e))?;
    let d: Vec<(HashAlgo, String)> = algos
        .iter()
        .map(|&a| (a, crate::hash::hash_bytes(bytes, a)))
        .collect();
    log.record(
        "output_written",
        Some(name),
        json!({"file": format!("{}/{}", PACKAGE_DIR, name), "kind": "manifest", "bytes": bytes.len(),
               "hashes": hashes_json(&d)}),
    )
    .map(|_| ())
    .map_err(|e| format!("audit log write failed: {}", e))
}

/// Why a live collection refuses an output folder on the system volume (`run` refuses before writing anything;
/// the phase repeats the check and records it).
pub fn same_volume_refusal(out_dir: &Path, drive: &str) -> String {
    format!(
        "the output folder {} is on the system volume {} of the machine being collected: writing there \
         can overwrite deleted data. Use a USB or network drive, or --allow-same-volume to accept it",
        out_dir.display(),
        drive
    )
}

/// Runs the collection phase. `Err` = the run cannot start (refused output volume, source that does not open);
/// the reason is already in the audit log as `run_failed`.
#[allow(clippy::too_many_arguments)]
pub fn collect_phase(
    opts: &CollectOptions,
    out_dir: &Path,
    report_dir: &Path,
    algos: &[HashAlgo],
    log: &mut AuditLog,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
    started: std::time::Instant,
) -> Result<PhaseResult, String> {
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);
    let fail = |log: &mut AuditLog, reason: String| -> Result<PhaseResult, String> {
        log.record("run_failed", None, json!({"reason": reason}))
            .map_err(io)?;
        Err(reason)
    };
    let live = opts.source == SourceSpec::Live;
    let elevated = host::is_elevated();
    let facts = host::facts();
    log.record(
        "collection_started",
        None,
        json!({"options": opts, "elevated": elevated, "system_drive": facts.system_drive}),
    )
    .map_err(io)?;
    sink(&Event::Phase {
        phase: "preflight".into(),
        total: 0,
    });

    let mut run_findings = vec![];
    if live {
        let same = host::same_volume(out_dir, &facts.system_drive);
        log.record(
            "output_volume_checked",
            Some(&out_dir.display().to_string()),
            json!({"system_drive": facts.system_drive, "same_volume": same, "allowed": opts.allow_same_volume}),
        )
        .map_err(io)?;
        if same && !opts.allow_same_volume {
            return fail(log, same_volume_refusal(out_dir, &facts.system_drive));
        }
        if same {
            run_findings.push(
                Finding::new(codes::OUTPUT_ON_SYSTEM_VOLUME, Severity::High)
                    .with("volume", facts.system_drive.clone())
                    .with("out", out_dir.display().to_string()),
            );
        }
    }
    let src = match super::open_source(&opts.source, elevated) {
        Ok(s) => s,
        Err(e) => return fail(log, e),
    };
    let described = src.describe();
    log.record("source_opened", None, described.clone())
        .map_err(io)?;

    let package_dir = report_dir.join(PACKAGE_DIR);
    if let Err(e) = std::fs::create_dir_all(&package_dir) {
        return fail(
            log,
            format!("cannot create {}: {}", package_dir.display(), e),
        );
    }
    let mut r = PhaseResult {
        elevated,
        ..PhaseResult::default()
    };

    // system.json: the collection host, the source and the options (always first in the package).
    let system = json!({"host": facts, "source": described, "options": opts, "elevated": elevated,
                        "tool": crate::TOOL_NAME, "version": crate::TOOL_VERSION});
    let mut b = serde_json::to_vec_pretty(&system).unwrap_or_default();
    b.push(b'\n');
    let c = match copy::write_snapshot(&package_dir, "system.json", &b, algos, run_findings) {
        Ok(c) => c,
        Err(e) => return fail(log, e),
    };
    record_collected(log, &c)?;
    r.collected.push(c);

    // Volatile first: it changes fastest.
    if opts.groups.contains(&Group::Volatile) {
        if live {
            sink(&Event::Phase {
                phase: "volatile".into(),
                total: 4,
            });
            let cap = volatile::capture(cancel);
            log.record(
                "volatile_captured",
                None,
                json!({"available": cap.available, "started_utc": cap.started_utc, "finished_utc": cap.finished_utc,
                       "processes": cap.processes.len(), "connections": cap.connections.len(),
                       "sessions": cap.sessions.len(), "services": cap.services.len(), "partial": cap.partial}),
            )
            .map_err(io)?;
            for (name, bytes) in cap.files() {
                let findings = cap
                    .partial_for(name)
                    .into_iter()
                    .map(|p| {
                        Finding::new(codes::VOLATILE_PARTIAL, Severity::Low)
                            .with("what", p.what.clone())
                            .with("incomplete", p.incomplete.to_string())
                            .with("of", p.of.to_string())
                            .with("reason", p.reason.clone())
                    })
                    .collect();
                let c = copy::write_snapshot(&package_dir, name, &bytes, algos, findings)?;
                record_collected(log, &c)?;
                sink(&Event::Artifact {
                    group: "volatile".into(),
                    source: c.source_display.clone(),
                    status: "collected".into(),
                    code: c
                        .findings
                        .iter()
                        .max_by_key(|f| f.severity)
                        .map(|f| f.code.clone())
                        .unwrap_or_default(),
                });
                r.collected.push(c);
            }
        } else {
            let n = NotCollected {
                group: Group::Volatile,
                source_path: "volatile".into(),
                source_display: "volatile".into(),
                reason: format!("a {} source has no running system", opts.source.kind()),
                finding: Finding::new(codes::NOT_AVAILABLE_FROM_SOURCE, Severity::Info)
                    .with("source", opts.source.kind()),
            };
            r.not_collected_seq.push(record_not_collected(log, &n)?);
            sink(&Event::Artifact {
                group: n.group.name().into(),
                source: n.source_display.clone(),
                status: "not_collected".into(),
                code: n.finding.code.clone(),
            });
            r.not_collected.push(n);
        }
    }

    // Files.
    let resolved = targets::resolve(src.as_ref(), &opts.groups, &opts.users);
    let mut per_group: BTreeMap<&str, u64> = BTreeMap::new();
    let mut files = vec![];
    for x in resolved {
        match x {
            Resolved::File(t) => {
                *per_group.entry(t.group.name()).or_default() += 1;
                files.push(t);
            }
            Resolved::Unlisted {
                group,
                path,
                error,
                message,
                raw_os_error,
            } => {
                let n = NotCollected {
                    group,
                    source_display: super::display_path(&src.display_prefix(), &path),
                    source_path: path,
                    reason: format!("folder not listed: {}", message),
                    finding: not_collected_finding(error, raw_os_error, &message, elevated, live),
                };
                r.not_collected_seq.push(record_not_collected(log, &n)?);
                sink(&Event::Artifact {
                    group: n.group.name().into(),
                    source: n.source_display.clone(),
                    status: "not_collected".into(),
                    code: n.finding.code.clone(),
                });
                r.not_collected.push(n);
            }
        }
    }
    log.record(
        "targets_resolved",
        None,
        json!({"files": files.len(), "per_group": per_group, "unlisted": r.not_collected.iter().filter(|n| n.group != Group::Volatile).count()}),
    )
    .map_err(io)?;
    sink(&Event::Phase {
        phase: "copy".into(),
        total: files.len() as u64,
    });

    let total = files.len() as u64;
    let mut bytes_done = 0u64;
    let mut last = std::time::Instant::now();
    for (i, t) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            r.cancelled = true;
            break;
        }
        let base = bytes_done;
        let mut on_chunk = |n: u64| {
            if last.elapsed() >= std::time::Duration::from_millis(150) {
                last = std::time::Instant::now();
                sink(&Event::Progress {
                    done: i as u64,
                    total,
                    bytes_done: base + n,
                    bytes_total: 0,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    eta_ms: None,
                });
            }
            !cancel.load(Ordering::Relaxed)
        };
        match copy::copy_one(
            src.as_ref(),
            t,
            &package_dir,
            algos,
            elevated,
            &mut on_chunk,
        ) {
            Outcome::Collected(c) => {
                bytes_done += c.bytes;
                record_collected(log, &c)?;
                sink(&Event::Artifact {
                    group: c.group.name().into(),
                    source: c.source_display.clone(),
                    status: "collected".into(),
                    code: c
                        .findings
                        .iter()
                        .max_by_key(|f| f.severity)
                        .map(|f| f.code.clone())
                        .unwrap_or_default(),
                });
                r.collected.push(*c);
            }
            Outcome::NotCollected(n) => {
                r.not_collected_seq.push(record_not_collected(log, &n)?);
                sink(&Event::Artifact {
                    group: n.group.name().into(),
                    source: n.source_display.clone(),
                    status: "not_collected".into(),
                    code: n.finding.code.clone(),
                });
                r.not_collected.push(n);
            }
            Outcome::Cancelled => {
                r.cancelled = true;
                break;
            }
        }
        sink(&Event::Progress {
            done: i as u64 + 1,
            total,
            bytes_done,
            bytes_total: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            eta_ms: None,
        });
    }

    let run_id = report_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (csv, js) = manifests(&r, algos, &described, &run_id);
    write_manifest(log, &package_dir, "manifest.csv", &csv, algos)?;
    write_manifest(log, &package_dir, "manifest.json", &js, algos)?;
    log.record(
        "collection_finished",
        None,
        json!({"collected": r.collected.len(), "not_collected": r.not_collected.len(), "bytes": bytes_done,
               "cancelled": r.cancelled}),
    )
    .map_err(io)?;
    Ok(r)
}
