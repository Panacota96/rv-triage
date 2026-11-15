//! End-to-end tests of the rv-triage binary: the collect workflow and the contract every Rakvor CLI must meet.
//!
//! The sample is examples/sample/source (a synthetic folder laid out like a Windows volume root), collected as a
//! directory source. Its ground truth was computed independently (Python hashlib, examples/sample/make_expected.py):
//! expected_hashes.csv (package paths, sizes, SHA-256, MD5) and expected_findings.json (finding codes).

use assert_cmd::Command;
use predicates::prelude::*;
use rv_triage_core::{CASE_ROLE, CaseRole, HashAlgo, RunConfig, run};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

const TOOL: &str = rv_triage_core::TOOL_NAME;

fn bin() -> Command {
    let mut c = Command::cargo_bin("rv-triage").unwrap();
    c.env("RV_NO_TIMESTAMP", "1"); // offline by default; trust_* tests use a local test TSA
    c
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn python() -> String {
    std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// The fake TSA process, killed when dropped, so a failing assertion cannot leave it running. An orphaned
/// server keeps the test's inherited stderr open: under `cargo test | tee` (CI) the step then never ends.
struct TsaServer(std::process::Child);

impl Drop for TsaServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts tests/fake_tsa.py (needs Python with pyhanko). Returns None to skip when unavailable.
fn test_pki(dir: &Path) -> Option<(TsaServer, String)> {
    let py = python();
    let script = root().join("tests/fake_tsa.py");
    let ok = std::process::Command::new(&py)
        .args(["-c", "import pyhanko"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!(
            "skipping trust test: {} has no pyhanko (pip install pyhanko)",
            py
        );
        return None;
    }
    let mut server = TsaServer(
        std::process::Command::new(&py)
            .arg(&script)
            .arg("serve")
            .arg(dir)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?,
    );
    let mut line = String::new();
    use std::io::BufRead;
    std::io::BufReader::new(server.0.stdout.take()?)
        .read_line(&mut line)
        .ok()?;
    Some((server, line.trim().to_string()))
}

/// The synthetic volume root collected by the sample run.
fn sample() -> PathBuf {
    root().join("examples/sample/source")
}

/// Three loose files used to seed a case folder through the core (the case machinery's reference input pipeline).
fn case_fixture() -> PathBuf {
    root().join("tests/fixtures/case-evidence")
}

fn only_dir(p: &Path) -> PathBuf {
    std::fs::read_dir(p)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

/// The value of a `  name: value` line of the run summary.
fn summary_value(stdout: &[u8], name: &str) -> String {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{}:", name)))
        .unwrap_or_else(|| panic!("no {} line in:\n{}", name, text))
        .trim()
        .to_string()
}

/// expected_hashes.csv: package path → (size, sha256, md5).
fn expected_hashes() -> BTreeMap<String, (u64, String, String)> {
    let text = std::fs::read_to_string(root().join("examples/sample/expected_hashes.csv")).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("package_path,size,sha256,md5"));
    lines
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            assert_eq!(f.len(), 4, "{}", l);
            (
                f[0].to_string(),
                (f[1].parse().unwrap(), f[2].to_string(), f[3].to_string()),
            )
        })
        .collect()
}

/// Every file under `dir`, as `/`-separated paths relative to it.
fn files_under(dir: &Path) -> Vec<String> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap();
                out.push(
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
        }
    }
    out.sort();
    out
}

fn collect_sample(out: &Path, extra: &[&str]) -> std::process::Output {
    bin()
        .args(["collect", "--source"])
        .arg(sample())
        .arg("--out")
        .arg(out)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn collect_help_has_every_required_section() {
    let out = bin().args(["collect", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "DESCRIPTION:",
        "Options:",
        "EXAMPLES:",
        "EXIT CODES:",
        "FILES WRITTEN:",
        "FORENSIC NOTES:",
    ] {
        assert!(text.contains(section), "missing {}", section);
    }
    let flags = [
        "--out",
        "--source",
        "--groups",
        "--users",
        "--allow-same-volume",
        "--hash",
        "--lang",
        "--actor",
        "--case",
        "--progress",
        "--jurisdiction",
        "--tsa-url",
        "--no-timestamp",
        "--sign-cert",
        "--sign-pass-env",
    ];
    for flag in flags {
        assert!(text.contains(flag), "missing {}", flag);
    }
    // The old scan options are gone (--case-dir only appears in the rv-hashinv example).
    for gone in ["--input", "--recursive", "--case-dir <", "--evidence"] {
        assert!(
            !text.contains(gone),
            "{} belongs to the old scan verb",
            gone
        );
    }
    // every option documents a default and an example
    assert!(
        text.matches("Default:").count() >= flags.len(),
        "each option needs a Default: line"
    );
    assert!(
        text.matches("Example:").count() >= flags.len(),
        "each option needs an Example: line"
    );
    // Forensic notes specific to a live collection, with Windows paths in the examples.
    for note in [
        "removable media",
        "raw NTFS",
        "NOT_COLLECTED_NO_ADMIN",
        "--allow-same-volume",
        "prefetch",
        "Amcache",
        "USB",
        "No RAM image",
        "E:\\triage",
        "package/",
        "manifest.csv",
        "manifest.json",
    ] {
        assert!(text.contains(note), "missing {}", note);
    }
    // Fixed width: nothing is re-wrapped past 100 columns.
    assert!(text.lines().all(|l| l.chars().count() <= 100));
    // The old verb is gone.
    bin().args(["scan", "--help"]).assert().code(2);
}

#[test]
fn out_is_required_with_a_clear_error() {
    bin()
        .args(["collect", "--source"])
        .arg(sample())
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("--out is required")
                .and(predicate::str::contains("USB or network drive")),
        );
}

#[test]
fn unknown_group_names_the_valid_groups() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["collect", "--groups", "hives,ram", "--source"])
        .arg(sample())
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "unknown group 'ram': use volatile, evtx, hives, prefetch, browsers, tasks or all",
        ));
    assert!(!out.path().join("logs").exists(), "nothing written");
}

#[test]
fn missing_source_is_refused_before_anything_is_written() {
    let out = tempfile::tempdir().unwrap();
    let missing = out.path().join("no-such-image.dd");
    bin()
        .args(["collect", "--progress", "none", "--source"])
        .arg(&missing)
        .arg("-o")
        .arg(out.path().join("out"))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no such file or folder"));
    assert!(!out.path().join("out").exists());
}

#[test]
fn three_hash_algorithms_are_a_usage_error() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["collect", "-o"])
        .arg(out.path())
        .args(["--hash", "md5,sha1,sha256"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("at most 2"));
}

#[test]
fn unknown_language_and_algorithm_are_usage_errors() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["collect", "--lang", "de", "-o"])
        .arg(out.path())
        .assert()
        .code(2);
    bin()
        .args(["collect", "--hash", "crc32", "-o"])
        .arg(out.path())
        .assert()
        .code(2);
}

/// The whole sample workflow: collect the synthetic volume, check the package and the findings against the
/// independently computed ground truth, verify the log with the tool and with the Python checker, then edit one
/// packaged file and expect both to catch it.
#[test]
fn collect_sample_matches_ground_truth_and_verifies() {
    let out = tempfile::tempdir().unwrap();
    let o = collect_sample(
        out.path(),
        &[
            "--hash",
            "sha256,md5",
            "--lang",
            "all",
            "--case",
            "T-1",
            "--actor",
            "ci",
            "--progress",
            "none",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    let expected = expected_hashes();
    let package = PathBuf::from(summary_value(&o.stdout, "package"));
    let logs = PathBuf::from(summary_value(&o.stdout, "logs"));
    assert_eq!(
        summary_value(&o.stdout, "source"),
        "directory",
        "source line"
    );
    let counts = summary_value(&o.stdout, "collected");
    assert!(
        counts.starts_with(&format!("{}  not collected: 1", expected.len() + 1)),
        "{}",
        counts
    );
    assert_eq!(summary_value(&o.stdout, "audit head").len(), 64);
    let next = summary_value(&o.stdout, "next");
    assert!(next.contains("rv-hashinv scan -i"), "{}", next);
    assert!(package.ends_with("package") && package.starts_with(out.path().join("reports")));

    // The package: exactly the expected artifact files, byte for byte (sizes and digests from Python hashlib).
    let files = files_under(&package);
    let artifacts: Vec<&String> = files
        .iter()
        .filter(|f| f.starts_with("artifacts/"))
        .collect();
    assert_eq!(
        artifacts,
        expected.keys().collect::<Vec<_>>(),
        "package artifacts"
    );
    for (rel, (size, sha256, md5)) in &expected {
        let bytes = std::fs::read(package.join(rel)).unwrap();
        assert_eq!(bytes.len() as u64, *size, "{}", rel);
        assert_eq!(
            &rv_triage_core::hash::hash_bytes(&bytes, HashAlgo::Sha256),
            sha256,
            "{}",
            rel
        );
        assert_eq!(
            &rv_triage_core::hash::hash_bytes(&bytes, HashAlgo::Md5),
            md5,
            "{}",
            rel
        );
    }
    for f in ["manifest.csv", "manifest.json", "volatile/system.json"] {
        assert!(files.contains(&f.to_string()), "{}", f);
    }
    // manifest.csv agrees with the ground truth too (what the lab will read).
    let manifest_csv = std::fs::read_to_string(package.join("manifest.csv")).unwrap();
    assert!(
        manifest_csv.starts_with(
            "package_path,group,source,method,bytes,sha256,md5,truncated_at,findings\n"
        ),
        "{}",
        manifest_csv
    );
    for (rel, (size, sha256, md5)) in &expected {
        let row = manifest_csv
            .lines()
            .find(|l| l.starts_with(&format!("{},", rel)))
            .unwrap_or_else(|| panic!("{} not in manifest.csv", rel));
        let f: Vec<&str> = row.rsplitn(6, ',').collect();
        // reversed: findings, truncated_at, md5, sha256, bytes, rest
        assert_eq!(
            (f[4], f[3], f[2], f[0]),
            (
                size.to_string().as_str(),
                sha256.as_str(),
                md5.as_str(),
                "COLLECTED_API"
            ),
            "{}",
            row
        );
    }

    // Findings: per package path, and the volatile group a folder cannot provide.
    let truth: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("examples/sample/expected_findings.json")).unwrap(),
    )
    .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(package.join("manifest.json")).unwrap()).unwrap();
    let got: serde_json::Map<String, serde_json::Value> = manifest["collected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["package_path"].as_str().unwrap().to_string(),
                c["findings"].clone(),
            )
        })
        .collect();
    assert_eq!(
        serde_json::Value::Object(got),
        truth["collected"],
        "collected findings"
    );
    let mut missing = serde_json::Map::new();
    for n in manifest["not_collected"].as_array().unwrap() {
        missing
            .entry(n["group"].as_str().unwrap())
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .unwrap()
            .push(n["finding"].clone());
    }
    assert_eq!(
        serde_json::Value::Object(missing),
        truth["not_collected"],
        "not collected"
    );
    assert_eq!(truth["exit_code"], 0);

    // The standard run outputs.
    let reports = package.parent().unwrap();
    for f in ["audit.jsonl", "audit.log", "hashes.csv", "environment.json"] {
        assert!(logs.join(f).is_file(), "{}", f);
    }
    for l in ["en", "es", "fr"] {
        for ext in ["html", "pdf"] {
            assert!(reports.join(format!("statistics.{}.{}", l, ext)).is_file());
        }
    }
    let items = std::fs::read_dir(reports.join("items")).unwrap().count();
    assert_eq!(
        items,
        expected.len() + 2,
        "one folder per packaged file + the volatile entry"
    );

    // verify-log: intact, every packaged file re-hashed.
    let ok = bin().arg("verify-log").arg(&logs).assert().code(0);
    let text = String::from_utf8_lossy(&ok.get_output().stdout).into_owned();
    assert!(text.contains("chain intact"), "{}", text);
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("outputs: "))
        .expect("outputs line");
    let (verified, rest) = line.split_once(" verified of ").unwrap();
    assert!(
        rest.starts_with(&format!("{} recorded (md5, sha256)", verified)),
        "{}",
        line
    );
    assert!(
        verified.parse::<usize>().unwrap() > expected.len() + 3,
        "{}",
        line
    );

    // The independent Python checker agrees.
    let oracle = root().join("tests/verify_chain.py");
    let py = python();
    let checked = std::process::Command::new(&py)
        .arg(&oracle)
        .arg(&logs)
        .output();
    let Ok(intact) = checked else {
        assert!(
            std::env::var("RV_TEST_PYTHON").is_err(),
            "RV_TEST_PYTHON={} does not run",
            py
        );
        eprintln!("skipped the Python checker: no {}", py);
        return;
    };
    let t = String::from_utf8_lossy(&intact.stdout);
    assert!(intact.status.success(), "{}", t);
    assert!(
        t.contains("chain: intact | register: matches | outputs: match"),
        "{}",
        t
    );

    // One packaged file edited after the run: verify-log exit 3 naming it, the Python checker MISMATCH.
    let victim = "artifacts/tasks/Windows/System32/Tasks/RakvorSampleUpdater";
    std::fs::write(package.join(victim), b"<Task>edited</Task>").unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains(format!(
            "output reports/package/{}",
            victim
        )));
    let edited = std::process::Command::new(&py)
        .arg(&oracle)
        .arg(&logs)
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&edited.stdout);
    assert_eq!(edited.status.code(), Some(3), "{}", t);
    assert!(t.contains("outputs: MISMATCH"), "{}", t);

    // Tampering with one audit entry is detected.
    let p = logs.join("audit.jsonl");
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        text.replacen("\"actor\":\"ci\"", "\"actor\":\"mallory\"", 1),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&p)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
}

#[test]
fn jsonl_progress_reports_phases_artifacts_and_elapsed_time() {
    let out = tempfile::tempdir().unwrap();
    let o = collect_sample(out.path(), &["--progress", "jsonl"]);
    assert_eq!(o.status.code(), Some(0));
    let text = String::from_utf8(o.stdout).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect();
    let phases: Vec<&str> = events
        .iter()
        .filter(|e| e["event"] == "phase")
        .map(|e| e["phase"].as_str().unwrap())
        .collect();
    assert_eq!(
        phases,
        ["preflight", "copy"],
        "no volatile phase for a folder"
    );
    let copy = events
        .iter()
        .find(|e| e["event"] == "phase" && e["phase"] == "copy")
        .unwrap();
    let n = expected_hashes().len() as u64;
    assert_eq!(copy["total"], n);
    let artifacts: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["event"] == "artifact").collect();
    assert_eq!(artifacts.len() as u64, n);
    assert!(artifacts.iter().all(|a| a["status"] == "collected"
        && a["code"] == "COLLECTED_API"
        && a["group"].is_string()
        && a["source"].is_string()));
    // Copy progress counts files (bytes_total 0); the verify pass after run_started counts bytes.
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "progress" && e["bytes_total"] == 0 && e["total"] == n)
    );
    let started = events
        .iter()
        .position(|e| e["event"] == "run_started")
        .unwrap();
    assert_eq!(events.last().unwrap()["event"], "run_finished");
    assert!(
        events[..started]
            .iter()
            .all(|e| e["event"] != "item_started")
    );
    let elapsed: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "progress")
        .map(|e| e["elapsed_ms"].as_u64().unwrap())
        .collect();
    assert!(
        !elapsed.is_empty() && elapsed.windows(2).all(|w| w[0] <= w[1]),
        "elapsed_ms must be monotonic"
    );
}

#[test]
fn groups_and_users_narrow_the_collection() {
    let out = tempfile::tempdir().unwrap();
    let o = collect_sample(
        out.path(),
        &[
            "--groups",
            "browsers,tasks",
            "--users",
            "ben.test",
            "--progress",
            "none",
        ],
    );
    assert_eq!(o.status.code(), Some(0));
    let package = PathBuf::from(summary_value(&o.stdout, "package"));
    let artifacts: Vec<String> = files_under(&package)
        .into_iter()
        .filter(|f| f.starts_with("artifacts/"))
        .collect();
    let want: Vec<String> = expected_hashes()
        .into_keys()
        .filter(|k| {
            k.starts_with("artifacts/tasks/") || k.starts_with("artifacts/browsers/Users/ben.test/")
        })
        .collect();
    assert_eq!(artifacts, want);
    assert!(summary_value(&o.stdout, "collected").contains("not collected: 0"));
}

#[test]
fn source_is_not_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("volume");
    for rel in files_under(&sample()) {
        let to = src.join(&rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(sample().join(&rel), &to).unwrap();
    }
    let state = |root: &Path| -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
        files_under(root)
            .into_iter()
            .map(|r| {
                let p = root.join(&r);
                let m = std::fs::metadata(&p).unwrap().modified().unwrap();
                (r, std::fs::read(&p).unwrap(), m)
            })
            .collect()
    };
    let before = state(&src);
    bin()
        .args(["collect", "--progress", "none", "--source"])
        .arg(&src)
        .arg("-o")
        .arg(tmp.path().join("out"))
        .assert()
        .code(0);
    assert_eq!(state(&src), before);
}

/// examples/sample/run.sh compares the package manifest with expected_hashes.csv and fails on a difference.
#[test]
#[cfg(unix)]
fn sample_script_compares_the_manifest() {
    let script = root().join("examples/sample/run.sh");
    let exe = env!("CARGO_BIN_EXE_rv-triage");
    let out = tempfile::tempdir().unwrap();
    let o = std::process::Command::new("sh")
        .arg(&script)
        .arg(exe)
        .env("RV_NO_TIMESTAMP", "1")
        .env("RV_SAMPLE_OUT", out.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", text);
    assert!(
        text.contains(&format!(
            "manifest.csv matches expected_hashes.csv ({} files",
            expected_hashes().len()
        )),
        "{}",
        text
    );
}

/// The sample is small, synthetic and binary-safe: under 200 KB, marked binary for git.
#[test]
fn sample_source_is_small_and_marked_binary() {
    let files = files_under(&sample());
    let total: u64 = files
        .iter()
        .map(|f| std::fs::metadata(sample().join(f)).unwrap().len())
        .sum();
    assert!(total < 200 * 1024, "{} bytes", total);
    let attrs = std::fs::read_to_string(root().join(".gitattributes")).unwrap();
    assert!(
        attrs
            .lines()
            .any(|l| l.trim() == "examples/sample/source/** binary")
    );
    for f in &files {
        let b = std::fs::read(sample().join(f)).unwrap();
        let s = String::from_utf8_lossy(&b);
        let utf16: String =
            char::decode_utf16(b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
                .map(|c| c.unwrap_or('?'))
                .collect();
        assert!(
            s.contains("RAKVOR SYNTHETIC SAMPLE") || utf16.contains("RAKVOR SYNTHETIC SAMPLE"),
            "{} is not marked synthetic",
            f
        );
    }
}

#[test]
fn describe_role_is_collection() {
    let o = bin().args(["describe", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["role"], "collection");
    assert_eq!(v["main_verb"], "collect");
}

#[test]
fn timestamp_of_a_missing_log_exits_3() {
    let d = tempfile::tempdir().unwrap();
    bin()
        .arg("timestamp")
        .arg(d.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no audit log at"));
}

#[test]
fn self_test_passes() {
    bin()
        .arg("self-test")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("FAIL").not());
}

#[test]
fn usage_doc_matches_help() {
    let generated = bin().arg("docs-cli").output().unwrap().stdout;
    let doc = root().join("docs/usage-cli.md");
    let committed = std::fs::read(&doc).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/usage-cli.md is out of date: run `cargo run -p rv-triage-cli -- docs-cli > docs/usage-cli.md`"
    );
}

/// Review (sidecar bypass): a copy of `logs` without its timestamp-*.json files. The audit log's
/// timestamp_obtained entries still name the tokens, so the missing metadata is a problem and the tokens are
/// still checked: with another CA bundle the chain is still refused.
fn sidecar_deletion_is_detected(logs: &Path, good_ca: &Path, other_ca: &Path) {
    let copy = tempfile::tempdir().unwrap();
    for e in std::fs::read_dir(logs).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_file() && !(name.starts_with("timestamp-") && name.ends_with(".json")) {
            std::fs::copy(&p, copy.path().join(&name)).unwrap();
        }
    }
    for ca in [good_ca, other_ca] {
        bin()
            .arg("verify-log")
            .arg(copy.path())
            .arg("--tsa-ca")
            .arg(ca)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("metadata"));
    }
    bin()
        .arg("verify-log")
        .arg(copy.path())
        .arg("--tsa-ca")
        .arg(other_ca)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("chain not validated"));
    bin().arg("verify-log").arg(copy.path()).assert().code(3);
}

/// The token checked from its metadata alone (log cut just before its timestamp_obtained entry, metadata digest
/// updated to the altered token): the TSA signature check catches the alteration.
fn altered_token_without_its_entry_fails_the_signature(
    logs: &Path,
    tsr: &Path,
    meta: &serde_json::Value,
) {
    let cut = tempfile::tempdir().unwrap();
    let covers = meta["covers_seq"].as_u64().unwrap();
    let kept: String = std::fs::read_to_string(logs.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"].as_u64() <= Some(covers)
        })
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(cut.path().join("audit.jsonl"), kept).unwrap();
    std::fs::copy(tsr, cut.path().join(tsr.file_name().unwrap())).unwrap();
    std::fs::write(
        cut.path()
            .join(tsr.with_extension("json").file_name().unwrap()),
        meta.to_string(),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(cut.path())
        .assert()
        .code(3)
        .stdout(predicate::str::contains("signature value does not verify"));
}

#[test]
fn trust_timestamp_signature_and_custody_with_test_pki() {
    let pki = tempfile::tempdir().unwrap();
    let Some((tsa, url)) = test_pki(pki.path()) else {
        return;
    };
    let out = tempfile::tempdir().unwrap();
    bin()
        .env_remove("RV_NO_TIMESTAMP")
        .env("NO_PROXY", "127.0.0.1")
        .env("RV_SIGN_PASSWORD", "test")
        .args(["collect", "--source"])
        .arg(sample())
        .args([
            "--jurisdiction",
            "fr",
            "--tsa-url",
            &url,
            "--progress",
            "none",
            "--sign-cert",
        ])
        .arg(pki.path().join("examiner.p12"))
        .arg("-o")
        .arg(out.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("timestamp: ok"));
    let logs = only_dir(&out.path().join("logs"));
    // The TSA's CMS signature is checked; the chain only with --tsa-ca.
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("TSA signature valid"))
        .stdout(predicate::str::contains("chain not checked"))
        .stdout(
            predicate::str::contains("covers entry").and(predicate::str::is_match(
                r"truncation: entries up to #\d+ are anchored by the RFC 3161 timestamp \(timestamp-\d{5}\.json\); 3 entries after it \(timestamp_obtained, statistics_report_written, run_finished\) cannot be proven complete",
            ).unwrap()),
        );
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(pki.path().join("ca.pem"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "chain validated to O=Rakvor TEST,CN=Rakvor TEST CA",
        ))
        .stdout(predicate::str::contains("chain not checked").not());
    // Another CA does not vouch for this TSA.
    let other = tempfile::tempdir().unwrap();
    let made = std::process::Command::new(
        std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into()),
    )
    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fake_tsa.py"))
    .arg("certs")
    .arg(other.path())
    .status()
    .unwrap();
    assert!(made.success());
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(other.path().join("ca.pem"))
        .assert()
        .code(3)
        .stdout(predicate::str::contains("chain not validated"));
    bin()
        .arg("verify-log")
        .arg(&logs)
        .arg("--tsa-ca")
        .arg(other.path().join("missing.pem"))
        .assert()
        .code(1);
    sidecar_deletion_is_detected(
        &logs,
        &pki.path().join("ca.pem"),
        &other.path().join("ca.pem"),
    );
    let item = only_dir(&only_dir(&out.path().join("reports")).join("items"));
    for f in [
        "custody.json",
        "custody.fr.pdf",
        "custody.fr.html",
        "custody.en.pdf",
    ] {
        assert!(item.join(f).is_file(), "{}", f);
    }
    let pdf = std::fs::read(item.join("technical.en.pdf")).unwrap();
    assert!(String::from_utf8_lossy(&pdf).contains("/adbe.pkcs7.detached"));
    // Independent check: pyHanko validates every signed PDF (intact + cryptographically valid; the test CA
    // is not a trusted root, so an untrusted chain is expected).
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/validate_pdf_signature.py");
    let v = std::process::Command::new(&py)
        .arg(&script)
        .arg(only_dir(&out.path().join("reports")))
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&v.stdout);
    assert!(v.status.success(), "pyHanko validation failed:\n{}", report);
    let lines: Vec<serde_json::Value> = report
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines.len() >= 8, "every PDF validated: {}", report);
    for l in &lines {
        assert_eq!(
            (&l["intact"], &l["valid"]),
            (&true.into(), &true.into()),
            "{}",
            l
        );
        assert!(l["signer"].as_str().unwrap().contains("Ana Ruiz"), "{}", l);
    }
    // The reports print the signer's certificate fingerprint, as logged at signing_certificate_loaded.
    let audit = std::fs::read_to_string(logs.join("audit.jsonl")).unwrap();
    let loaded: serde_json::Value = audit
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|e| e["action"] == "signing_certificate_loaded")
        .unwrap();
    let fp = loaded["details"]["certificate_sha256"].as_str().unwrap();
    assert_eq!(fp.len(), 64);
    assert!(
        std::fs::read_to_string(item.join("technical.en.html"))
            .unwrap()
            .contains(fp)
    );
    // Removing entries back to (and including) the timestamped one is detected through covers_seq.
    let audit_path = logs.join("audit.jsonl");
    let full = std::fs::read_to_string(&audit_path).unwrap();
    let kept: Vec<&str> = full.lines().collect();
    std::fs::write(
        &audit_path,
        format!("{}\n", kept[..kept.len() - 4].join("\n")),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("truncated: timestamp-"));
    std::fs::write(&audit_path, &full).unwrap();
    // Tampering with the token is detected.
    let tsr = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "tsr"))
        .unwrap();
    let mut b = std::fs::read(&tsr).unwrap();
    // The last byte of a token is the last byte of the TSA's RSA signature value.
    let last = b.len() - 1;
    b[last] ^= 0xff;
    std::fs::write(&tsr, &b).unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("missing or altered"));
    // Updating the digest in the metadata file does not help: the audit log's timestamp_obtained entry is what
    // the token is checked against, and the metadata now disagrees with it.
    let meta_path = tsr.with_extension("json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["token_sha256"] = rv_triage_core::hash::hash_bytes(&b, HashAlgo::Sha256).into();
    std::fs::write(&meta_path, meta.to_string()).unwrap();
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("missing or altered"));
    altered_token_without_its_entry_fails_the_signature(&logs, &tsr, &meta);
    // Offline run: pending, then added later with `timestamp`.
    let out2 = tempfile::tempdir().unwrap();
    bin()
        .env_remove("RV_NO_TIMESTAMP")
        .args(["collect", "--source"])
        .arg(sample())
        .args([
            "--tsa-url",
            "http://127.0.0.1:9/tsr",
            "--progress",
            "none",
            "-o",
        ])
        .arg(out2.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("timestamp: pending"));
    let logs2 = only_dir(&out2.path().join("logs"));
    bin()
        .env("NO_PROXY", "127.0.0.1")
        .args(["timestamp"])
        .arg(&logs2)
        .args(["--tsa-url", &url])
        .assert()
        .code(0);
    bin()
        .arg("verify-log")
        .arg(&logs2)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("covers entry"));
    drop(tsa);
}

/// A case-folder run made through the core (the reference input pipeline kept for the case machinery):
/// `collect` hands its package to rv-hashinv instead of writing to a case folder, so the CLI has no case
/// options; verify-case and verify-log must still check cases written by the other Rakvor tools.
fn core_case_run(case: &Path, case_id: Option<&str>, role: CaseRole) -> Result<PathBuf, String> {
    let cfg = RunConfig {
        inputs: vec![case_fixture()],
        algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
        actor: "seed".into(),
        case_id: case_id.map(String::from),
        jurisdiction: "fr".into(),
        case_dir: Some(case.to_path_buf()),
        case_role: role,
        ..Default::default()
    };
    run(&cfg, &mut |_| {}, &AtomicBool::new(false))
        .map(|s| s.log_dir.parent().unwrap().to_path_buf())
}

#[test]
fn verify_case_and_verify_log_on_a_case_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("CASE-1");
    core_case_run(&case, Some("CASE-1"), CaseRole::Intake).unwrap();
    let run_dir = core_case_run(&case, None, CASE_ROLE).unwrap();
    for f in [
        "case.json",
        "case-log.jsonl",
        "evidence/registry.json",
        "evidence/registry.csv",
    ] {
        assert!(case.join(f).is_file(), "{}", f);
    }
    assert!(run_dir.starts_with(case.join("runs").join(TOOL)));
    // verify-log of a run in a case: its end is anchored by run_finished in the case log.
    let run_logs = run_dir.join("logs");
    bin()
        .arg("verify-log")
        .arg(&run_logs)
        .assert()
        .code(0)
        .stdout(
            predicate::str::is_match(
                r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)",
            )
            .unwrap(),
        );
    let audit_path = run_logs.join("audit.jsonl");
    let full = std::fs::read_to_string(&audit_path).unwrap();
    let kept: Vec<&str> = full.lines().collect();
    std::fs::write(
        &audit_path,
        format!("{}\n", kept[..kept.len() - 1].join("\n")),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&run_logs)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("truncated: the case log records"));
    std::fs::write(&audit_path, &full).unwrap();
    bin().arg("verify-case").arg(&case).assert().code(0).stdout(
        predicate::str::contains("3 registered items, 2 runs verified").and(
            predicate::str::is_match(r"outputs: [1-9]\d* verified of [1-9]\d* recorded").unwrap(),
        ),
    );
    // verify-case re-hashes every run's recorded outputs: an edited report is named, exit 3.
    let stats = run_dir.join("reports/statistics.json");
    let saved = std::fs::read(&stats).unwrap();
    std::fs::write(&stats, b"{}\n").unwrap();
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(3)
        .stdout(predicate::str::contains(
            "output reports/statistics.json: md5 differs from audit entry #",
        ));
    std::fs::write(&stats, saved).unwrap();
    bin()
        .args(["verify-case", "--rehash"])
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "re-hashed 3 of 3 registered items: 3 match the registry",
        ));
    bin().arg("verify-case").arg(tmp.path()).assert().code(1);

    // A tampered case log: verify-case exit 3, and no run extends the case.
    let log = case.join("case-log.jsonl");
    let original = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, original.replacen("CASE-1", "CASE-X", 1)).unwrap();
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
    let runs = |c: &Path| {
        std::fs::read_dir(c.join("runs").join(TOOL))
            .unwrap()
            .count()
    };
    let before = runs(&case);
    assert!(core_case_run(&case, None, CASE_ROLE).is_err());
    assert_eq!(runs(&case), before, "no run folder in a broken case");
    std::fs::write(&log, &original).unwrap();
    // A tampered registry: detected through the digest recorded in the case log.
    let reg = case.join("evidence/registry.json");
    let text = std::fs::read_to_string(&reg).unwrap();
    std::fs::write(&reg, text.replacen("\"size\": ", "\"size\": 1", 1)).unwrap();
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("registry.json"));
}
/// Cross-profile check without the other repository: a case folder written by the other profile
/// (tests/golden/case-by-<profile>.zip.b64, made by tests/golden/regenerate.py) verifies here, and tampering with it is
/// still detected. Unpacked with tests/golden/unpack.py (RV_TEST_PYTHON), like the other Python-based oracles.
#[test]
fn golden_case_from_the_other_profile_verifies() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden");
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&golden)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    archives.retain(|p| p.to_string_lossy().ends_with(".zip.b64"));
    archives.sort();
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    for archive in archives {
        let tmp = tempfile::tempdir().unwrap();
        let unzip = std::process::Command::new(&py)
            .arg(golden.join("unpack.py"))
            .arg(&archive)
            .arg(tmp.path())
            .status();
        if !unzip.is_ok_and(|s| s.success()) {
            eprintln!(
                "skipping golden case test: {} cannot unpack {}",
                py,
                archive.display()
            );
            return;
        }
        let case = tmp.path().join("CASE-GOLDEN");
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(0)
            .stdout(predicate::str::contains(
                "3 registered items, 1 runs verified",
            ));
        let logs = only_dir(&only_dir(&case.join("runs"))).join("logs");
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(0)
            .stdout(
                predicate::str::contains("covers entry #").and(
                    predicate::str::is_match(
                        r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)",
                    )
                    .unwrap(),
                ),
            );
        let audit = logs.join("audit.jsonl");
        let full = std::fs::read(&audit).unwrap();
        let cut = full[..full.len() - 1]
            .iter()
            .rposition(|&b| b == b'\n')
            .unwrap()
            + 1;
        std::fs::write(&audit, &full[..cut]).unwrap();
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("truncated: the case log records"));
        bin().arg("verify-case").arg(&case).assert().code(3);
        std::fs::write(&audit, &full).unwrap();
        // verify-case checks each token against its timestamp_obtained entry: an altered signature value, even
        // with the digest in the metadata file updated to match, makes the case fail (the entry's digest differs).
        let tsr = std::fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "tsr"))
            .unwrap();
        let meta_path = tsr.with_extension("json");
        let (token, meta_text) = (
            std::fs::read(&tsr).unwrap(),
            std::fs::read_to_string(&meta_path).unwrap(),
        );
        let mut b = token.clone();
        let last = b.len() - 1;
        b[last] ^= 0xff;
        std::fs::write(&tsr, &b).unwrap();
        let mut meta: serde_json::Value = serde_json::from_str(&meta_text).unwrap();
        meta["token_sha256"] = rv_triage_core::hash::hash_bytes(&b, HashAlgo::Sha256).into();
        std::fs::write(&meta_path, meta.to_string()).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("missing or altered"));
        std::fs::write(&tsr, &token).unwrap();
        // Review (sidecar bypass): deleting the metadata file does not skip the token's checks.
        std::fs::remove_file(&meta_path).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("metadata"));
        std::fs::write(&meta_path, &meta_text).unwrap();
        bin().arg("verify-case").arg(&case).assert().code(0);
        let reg = case.join("evidence/registry.json");
        let text = std::fs::read_to_string(&reg).unwrap();
        std::fs::write(&reg, text.replacen("\"size\": ", "\"size\": 1", 1)).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("registry.json"));
    }
}

/// CI and release build with the toolchain pinned in rust-toolchain.toml (never a floating `stable`).
#[test]
fn workflows_use_the_pinned_toolchain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(root.join("rust-toolchain.toml")).unwrap();
    let channel = pin
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    assert!(
        channel.split('.').count() == 3 && channel.split('.').all(|p| p.parse::<u32>().is_ok()),
        "rust-toolchain.toml must pin an exact x.y.z version, not {}",
        channel
    );
    for wf in ["ci.yml", "release.yml"] {
        let text = std::fs::read_to_string(root.join(".github/workflows").join(wf)).unwrap();
        assert!(!text.contains("rust-toolchain@stable"), "{}", wf);
        assert!(text.contains("rustup toolchain install"), "{}", wf);
    }
}
