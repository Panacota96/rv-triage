//! rv-triage command-line interface. All work happens in `rv_triage_core`; this file only
//! parses arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rv_triage_core::collect::{CollectOptions, Group, SourceSpec};
use rv_triage_core::trust::{self, DEFAULT_TSA};
use rv_triage_core::{
    CASE_ROLE, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, audit, case, hash, i18n, run,
    verify,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

/// The CLI command that does the tool's main work (`.forge.json` run_command, `describe` main_verb).
const MAIN_VERB: &str = "collect";

const ABOUT: &str = "Collect volatile data and key Windows artifacts from a live machine into a hashed, audit-logged package for the lab.";

const LONG_ABOUT: &str = "\
DESCRIPTION:
  rv-triage runs from a USB stick on a live Windows 10/11 machine and collects, into one package:
    1. preflight: checks elevation and that the output folder is not on the system volume of the
       machine being collected; records the host (name, OS, time, system drive);
    2. volatile data first, because it changes fastest: processes, network connections, logon
       sessions and services (volatile/*.json);
    3. files of each group: registry hives (system and per user), event logs, prefetch, browser
       history (Edge, Chrome, Firefox) and scheduled tasks. Each file is read once: the bytes are
       hashed with one or two algorithms while they are written to the package, and the file is
       stat'ed before and after (CHANGED_DURING_COPY if it moved);
    4. writes manifest.csv and manifest.json, then re-reads every packaged file and compares it
       with the digests taken during the copy (COPY_REREAD_MISMATCH);
    5. writes the statistics report, one technical report, summary and custody form per packaged
       file, and a hash-chained audit log that `rv-triage verify-log` checks later.
  A file that cannot be read (locked, no administrator rights, error) is listed as not collected,
  with the reason; the run continues. The examiner then registers the package in the lab with
  rv-hashinv (case folder, evidence ids).";

const COLLECT_AFTER_HELP: &str = "\
EXAMPLES:
  Collect everything from the running system onto the USB drive E: (run as administrator):
    rv-triage collect --out E:\\triage --case CASE-2026-014 --actor \"Ana Ruiz\"
  Only event logs and registry hives, SHA-256 + MD5, Spanish reports, one user profile:
    rv-triage collect -o E:\\triage --groups evtx,hives --users ana.ruiz --hash sha256,md5 --lang es
  Rehearse on a mounted image or a test folder, reports in three languages, JSON events:
    rv-triage collect -s D:\\mounted-c -o E:\\triage --lang all --progress jsonl > events.jsonl
  Verify the audit log and every packaged file afterwards:
    rv-triage verify-log E:\\triage\\logs\\<RUN-ID>
  In the lab, register the package in the case folder:
    rv-hashinv scan -i E:\\triage\\reports\\<RUN-ID>\\package -r --case-dir F:\\CASE-014

EXIT CODES:
  0    Completed; no high-severity finding (files not collected for lack of rights or locks
       are medium or low findings, listed in the reports).
  1    Runtime error (--source not found or not readable, output not writable, output on the
       system volume without --allow-same-volume). See the audit log when one was created.
  2    Usage error (--out missing, unknown option or group, more than two hash algorithms,
       unsupported language).
  3    Completed with at least one high-severity finding: a file read only in part
       (PARTIAL_READ), a packaged copy that differs from what was read (COPY_REREAD_MISMATCH),
       or the package written on the system volume (OUTPUT_ON_SYSTEM_VOLUME).
  130  Cancelled with Ctrl+C. Partial package, reports and the cancellation are in the audit log.

FILES WRITTEN:
  <OUT>/reports/<RUN-ID>/package/         The package to hand over to the lab:
    volatile/system.json                  Collection host, source, options, elevation.
    volatile/<NAME>.json                  Processes, connections, sessions, services (live only).
    artifacts/<GROUP>/<PATH ON VOLUME>    Each copied file at its path on the volume, e.g.
                                          artifacts/hives/Windows/System32/config/SAM.
    manifest.csv                          One row per packaged file: path, group, source,
                                          method (raw|api|snapshot), bytes, digests, findings.
    manifest.json                         The same, plus every file not collected and why.
  <OUT>/logs/<RUN-ID>/audit.jsonl         Hash-chained log of every action (JSON Lines).
  <OUT>/logs/<RUN-ID>/audit.log           The same actions, human-readable.
  <OUT>/logs/<RUN-ID>/hashes.csv          Hash register of the packaged files (re-read).
  <OUT>/logs/<RUN-ID>/environment.json    Tool and dependency versions, OS, host, user, command.
  <OUT>/logs/<RUN-ID>/timestamp-<SEQ>.tsr|.json  RFC 3161 token for the audit chain head.
  <OUT>/reports/<RUN-ID>/statistics.json  Run statistics (+ statistics.<LANG>.html and .pdf).
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/technical|summary.json|.<LANG>.html|.<LANG>.pdf
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/custody.json|.<es|fr>.html|.pdf|.en.html|.pdf

FORENSIC NOTES:
  - Run from removable media (USB or network drive) and write the package there: --out on the
    system volume of the machine being collected is refused (it can overwrite deleted data)
    unless --allow-same-volume, which adds the high finding OUTPUT_ON_SYSTEM_VOLUME.
  - Elevated (Run as administrator): files are read from the raw NTFS volume, so locked hives
    and event logs are collected (method raw). Not elevated: the normal file API is used; locked
    files and other users' profiles are listed as NOT_COLLECTED_NO_ADMIN and the run continues.
  - Running the tool leaves its own traces on the machine: a prefetch file for rv-triage.exe,
    Amcache / ShimCache entries, USB device entries (USBSTOR, setupapi.dev.log) and event log
    records. Note the time of the run so they can be told apart from the user's activity.
  - No RAM image is taken: volatile/*.json is what the Windows APIs report, not a memory dump.
    Capture memory with a dedicated tool first if it matters.
  - Every packaged file is hashed while it is read and re-read from the package afterwards; the
    source is opened read-only. A finding says how a copy was made, never what it means.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`, which also re-hashes every packaged file. Removing the
    last lines is detected only against the RFC 3161 timestamp: keep the log with the package.
  - MD5 and SHA-1 are accepted for compatibility; pair them with SHA-256 or BLAKE3.
  - Offline? The run finishes with `timestamp_pending`; run `rv-triage timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never
    logged.";

#[derive(Parser)]
#[command(name = TOOL_NAME, version = TOOL_VERSION, about = ABOUT, long_about = LONG_ABOUT, max_term_width = 100,
          after_long_help = "Run `rv-triage <COMMAND> --help` for the options, examples and exit codes of each command.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collect volatile data and Windows artifacts into a hashed, audit-logged package.
    #[command(long_about = LONG_ABOUT, after_long_help = COLLECT_AFTER_HELP)]
    Collect(Box<CollectArgs>),
    /// Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.
    #[command(after_long_help = "\
CHECKS:
  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry
    breaks it;
  - every timestamp token the log records (timestamp_obtained) is still next to it with its
    metadata (timestamp-<SEQ>.tsr with the recorded SHA-256, timestamp-<SEQ>.json agreeing): a
    missing file is a problem, never a skipped check; a token file no entry records is checked
    too. Every token covers the hash of the entry it names;
  - the TSA's CMS signature of every token: signer certificate in the token, ESS
    signing-certificate binding, message digest over TSTInfo, RSA signature, and an extended key
    usage that is critical and only timeStamping (RFC 3161). With --tsa-ca, also the TSA
    certificate path up to that CA bundle at the token's genTime (every candidate issuer tried;
    CA flag, keyCertSign, pathLenConstraint, directoryName name constraints, no unsupported
    critical extension); without it the output says \"chain not checked\". Revocation is
    never checked: establish it from CRL/OCSP evidence covering genTime;
  - truncation: a chain alone cannot show that entries were removed from its end. The log must
    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside
    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log
    recorded at run_finished (only timestamp_obtained may follow). Entries after the last
    anchored one are listed as not provable; with neither record the output says
    \"truncation not detectable without a timestamp or case record\";
  - recorded outputs: every file the log says the run wrote (package files and manifests,
    item reports, statistics, hashes.csv, environment.json) is re-hashed with each algorithm recorded and compared; the
    latest entry for a file wins. A missing, edited or replaced file is a problem; a recorded
    path that is absolute, contains .. or resolves outside the run folder (symlink, junction)
    is rejected and not read. Timestamp tokens (checked above) and files written outside the
    run folder are listed as not re-hashed, with the reason. Output: \"outputs: N verified of
    M recorded (algorithms)\".

EXAMPLES:
  rv-triage verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl
  rv-triage verify-log rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-triage verify-log E:\\CASE-014\\runs\\rv-triage\\20261019T101500Z-a1b2c3\\logs
  rv-triage verify-log rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-ca digicert-tsa-roots.pem

EXIT CODES:
  0  The chain is intact and agrees with its timestamps and case record (if any), and every
     output file it records (package, reports, hashes.csv, environment.json) still has the
     recorded digests.
  1  The log or the --tsa-ca file cannot be read.
  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not
     match or does not verify (altered token, invalid TSA signature, chain not trusted by
     --tsa-ca), the log is shorter than its timestamp or case record says (truncated), or
     a recorded output file was edited, deleted or replaced after the run (named in the
     output; a recorded path that leads outside the run folder is rejected, not read).")]
    VerifyLog {
        /// Path to audit.jsonl, or to the run's log folder that contains it.
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// CA bundle (PEM with one or more certificates, or one DER certificate) that the TSA
        /// certificate of every timestamp token must chain to, at the token's genTime.
        ///
        /// Default: none (the TSA signature is checked, the chain is not).
        /// Example: --tsa-ca C:\certs\tsa-roots.pem
        #[arg(long, value_name = "PEM", verbatim_doc_comment)]
        tsa_ca: Option<PathBuf>,
    },
    /// Check every hash algorithm against known-answer test vectors.
    #[command(after_long_help = "\
EXAMPLES:
  rv-triage self-test

EXIT CODES:
  0  All algorithms give the published answer for the input \"abc\".
  1  At least one algorithm failed: do not use this build for evidence.")]
    SelfTest,
    /// Add an RFC 3161 timestamp to a finished run (e.g. after working offline).
    #[command(after_long_help = "\
EXAMPLES:
  rv-triage timestamp rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-triage timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr

EXIT CODES:
  0  Timestamp obtained and logged.
  1  The TSA could not be reached (nothing changed; try again).
  3  The log is missing or broken: no timestamp is added.")]
    Timestamp {
        /// The run's log folder (or its audit.jsonl).
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// RFC 3161 time-stamping authority.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Name written in the new audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
    },
    /// Verify a whole case folder: case log, evidence registry and every run's audit log.
    #[command(after_long_help = "\
CHECKS:
  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;
  - evidence/registry.json has the SHA-256 recorded at the last registry change;
  - every run announced in the case log has an intact audit.jsonl (and valid timestamp
    tokens: imprint and TSA signature; the TSA chain is not checked, use verify-log
    --tsa-ca), its case_linked entry points to its run_started entry, and the audit head
    recorded at run_finished is its final entry (only timestamp_obtained may follow);
  - every output file a run's audit log records (reports, hashes.csv, environment.json) is
    re-hashed and compared with the recorded digests (edited, deleted or replaced: a problem);
  - with --rehash: every registered item still reachable at its registered path is read again
    and its digests are compared with the registry (the latest registration of a path).

EXAMPLES:
  rv-triage verify-case E:\\CASE-014
  rv-triage verify-case E:\\CASE-014 --rehash

EXIT CODES:
  0  The case folder is intact (warnings, e.g. a run still in progress or an item not
     reachable for --rehash, are printed).
  1  The folder is not a case folder (no case.json).
  3  At least one check failed: the case was edited, truncated or re-ordered, a run's
     recorded output (report, register) was edited, deleted or replaced, or (--rehash) an
     evidence file differs from the registry.")]
    VerifyCase {
        /// The case folder (the one that holds case.json).
        ///
        /// Example: E:\CASE-014
        case: PathBuf,
        /// Also re-hash every registered item still reachable and compare it with the registry.
        /// Default: off (only the registry's digest is checked)
        /// Example: --rehash
        #[arg(long, verbatim_doc_comment)]
        rehash: bool,
    },
    /// Print the full help of every command as Markdown (used to generate docs/usage-cli.md).
    #[command(hide = true)]
    DocsCli,
    /// Describe this tool as JSON (schema rakvor.describe/1) for RV Hub and scripts.
    #[command(hide = true, after_long_help = DESCRIBE_AFTER_HELP)]
    Describe {
        /// Print JSON: one pretty-printed object with sorted keys.
        /// Default: on (JSON is the only format)
        /// Example: --json
        #[arg(long, verbatim_doc_comment)]
        json: bool,
    },
}

const DESCRIBE_AFTER_HELP: &str = "DESCRIPTION:
  Prints what this tool is, what it accepts and how to launch it, validated by
  schemas/describe.schema.json. RV Hub reads it to list the tool and start it.
  Fields: schema, tool, title, version, role (collection: it reads a live system, an image
  or a folder, and its package is registered later with rv-hashinv), main_verb (collect),
  accepts (empty: no evidence file is an input), case_formats, log_formats, cli_exe,
  gui_exe, exit_codes. Nothing is read or written; no audit log is created.

EXAMPLES:
  rv-triage describe --json

EXIT CODES:
  0  The description was printed.";

#[derive(Clone, Copy, ValueEnum)]
enum ProgressMode {
    /// Progress bar with elapsed time, files or bytes done and ETA on stderr.
    Bar,
    /// One JSON event per line on stdout (for scripts and other tools).
    Jsonl,
    /// No progress output; only the final summary.
    None,
}

#[derive(Args)]
struct CollectArgs {
    /// Folder where logs/ and reports/ (with the package) are created. Created if missing.
    /// Required: choose the USB or network drive; the system volume of the machine being
    /// collected is refused unless --allow-same-volume.
    /// Default: none (required)
    /// Example: --out E:\triage
    #[arg(short, long, value_name = "DIR", verbatim_doc_comment)]
    out: Option<PathBuf>,

    /// What to collect from: live (the running Windows system), a raw NTFS volume image
    /// file (.dd, .img, .raw) or a folder laid out like a volume root (a mounted image, a
    /// test set). Volatile data exists only for live.
    /// Default: live
    /// Example: --source D:\images\laptop-c.dd   or   --source examples\sample\source
    #[arg(
        short,
        long,
        value_name = "SRC",
        default_value = "live",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    source: String,

    /// Artifact groups, comma-separated: volatile, evtx, hives, prefetch, browsers, tasks,
    /// or all.
    /// Default: all
    /// Example: --groups volatile,evtx,hives
    #[arg(
        short,
        long,
        value_name = "LIST",
        default_value = "all",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    groups: String,

    /// Only these user profiles (folder names under Users\), comma-separated or repeated.
    /// Applies to the per-user hives and the browser history.
    /// Default: every profile
    /// Example: --users ana.ruiz,ben.test
    #[arg(
        short,
        long,
        value_name = "NAMES",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    users: Vec<String>,

    /// Accept an output folder on the system volume of the machine being collected (live
    /// source). Writing there can overwrite deleted data: the run gets the high finding
    /// OUTPUT_ON_SYSTEM_VOLUME (exit code 3).
    /// Default: off (refused, exit code 1)
    /// Example: --allow-same-volume
    #[arg(long, verbatim_doc_comment)]
    allow_same_volume: bool,

    /// Hash algorithm(s): one or two of md5, sha1, sha256, sha512, sha3-256, blake3.
    /// Both are computed in the same read of each file. More than two is refused (exit 2).
    /// Default: sha256
    /// Example: --hash sha256,md5   or   --hash sha256 --hash blake3
    #[arg(
        short = 'H',
        long = "hash",
        value_name = "ALGO",
        value_delimiter = ',',
        default_value = "sha256",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    hashes: Vec<String>,

    /// Report language: en, es, fr, or all (one HTML and PDF per language). JSON is
    /// language-neutral.
    /// Default: en
    /// Example: --lang es   or   --lang all
    #[arg(
        short,
        long,
        value_name = "LANG",
        default_value = "en",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    lang: String,

    /// Name of the examiner, written in every audit entry and report.
    /// Default: the operating-system user name
    /// Example: --actor "Ana Ruiz"
    #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
    actor: Option<String>,

    /// Case or engagement identifier printed on the reports.
    /// Default: none
    /// Example: --case CASE-2026-014
    #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
    case_id: Option<String>,

    /// How progress is shown: bar, jsonl or none.
    /// Default: bar (hidden automatically when stderr is not a terminal)
    /// Example: --progress jsonl
    #[arg(
        short,
        long,
        value_enum,
        value_name = "MODE",
        default_value = "bar",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    progress: ProgressMode,

    /// Chain-of-custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France,
    /// scellés, French). An English copy is always added.
    /// Default: co
    /// Example: --jurisdiction fr
    #[arg(short, long, value_name = "CC", default_value = "co", value_parser = ["co", "fr"], verbatim_doc_comment, hide_default_value = true, hide_possible_values = true)]
    jurisdiction: String,

    /// RFC 3161 time-stamping authority for the audit chain head.
    /// Default: http://timestamp.digicert.com
    /// Example: --tsa-url https://freetsa.org/tsr
    #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
    tsa_url: String,

    /// Do not request a trusted timestamp (offline). Also set by RV_NO_TIMESTAMP=1.
    /// Default: off (a timestamp is requested)
    /// Example: --no-timestamp
    #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
    no_timestamp: bool,

    /// Examiner's certificate (.p12/.pfx, RSA) used to sign every PDF report. The password
    /// is read from the environment variable named by --sign-pass-env, or asked for
    /// interactively.
    /// Default: none (PDFs are not signed)
    /// Example: --sign-cert E:\certs\ana-ruiz.p12
    #[arg(long, value_name = "P12", verbatim_doc_comment)]
    sign_cert: Option<PathBuf>,

    /// Environment variable holding the certificate password.
    /// Default: RV_SIGN_PASSWORD
    /// Example: --sign-pass-env CERT_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_SIGN_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    sign_pass_env: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ExitCode::from(match cli.command {
        Command::Collect(a) => collect(*a),
        Command::VerifyLog { log, tsa_ca } => verify_log(log, tsa_ca),
        Command::VerifyCase { case, rehash } => verify_case(case, rehash),
        Command::SelfTest => self_test(),
        Command::Timestamp {
            log,
            tsa_url,
            actor,
        } => timestamp(log, tsa_url, actor),
        Command::DocsCli => {
            print!("{}", docs_cli());
            EXIT_OK
        }
        Command::Describe { json: _ } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&describe()).expect("describe is valid JSON")
            );
            EXIT_OK
        }
    })
}

fn usage_error(msg: &str) -> u8 {
    eprintln!(
        "error: {}\n\nFor more information, try 'rv-triage {} --help'.",
        msg, MAIN_VERB
    );
    EXIT_USAGE
}

/// `--source`: `live`, or an existing image file or folder. A path that does not exist is refused here, before
/// any output is created, so a typo never starts a collection of the wrong thing.
fn parse_source(s: &str) -> Result<SourceSpec, String> {
    if s.trim().is_empty() {
        return Err("--source is empty: use live, an image file or a folder".into());
    }
    if !s.eq_ignore_ascii_case("live") && !Path::new(s).exists() {
        return Err(format!(
            "--source {}: no such file or folder (use live, a volume image file or a folder laid out \
             like a volume root)",
            s
        ));
    }
    Ok(SourceSpec::parse(s))
}

/// Text-mode line for an artifact event: only what the examiner must notice (not collected, or a finding
/// above info). `None` for an ordinary collected file.
fn artifact_line(group: &str, source: &str, status: &str, code: &str) -> Option<String> {
    use rv_triage_core::collect::codes;
    if status == "not_collected" {
        return Some(format!("not collected: [{}] {} ({})", group, source, code));
    }
    if code.is_empty()
        || code == codes::COLLECTED_API
        || code == codes::COLLECTED_RAW
        || code == codes::CAPTURED_SNAPSHOT
    {
        return None;
    }
    Some(format!("warning: [{}] {}: {}", group, source, code))
}

fn phase_line(phase: &str, total: u64) -> String {
    match (phase, total) {
        (_, 0) => format!("phase: {}", phase),
        ("copy", n) => format!("phase: copy ({} files)", n),
        (p, n) => format!("phase: {} ({} steps)", p, n),
    }
}

/// Counts and elevation read back from the package this run wrote (manifest.json, volatile/system.json).
struct PackageFacts {
    collected: Option<usize>,
    not_collected: Option<usize>,
    elevated: Option<bool>,
    source_kind: Option<String>,
}

fn package_facts(package: &Path) -> PackageFacts {
    let read = |p: PathBuf| -> Option<serde_json::Value> {
        serde_json::from_slice(&std::fs::read(p).ok()?).ok()
    };
    let manifest = read(package.join("manifest.json"));
    let system = read(package.join("volatile").join("system.json"));
    let count = |k: &str| {
        manifest
            .as_ref()
            .and_then(|m| m[k].as_array())
            .map(|a| a.len())
    };
    PackageFacts {
        collected: count("collected"),
        not_collected: count("not_collected"),
        elevated: system.as_ref().and_then(|s| s["elevated"].as_bool()),
        source_kind: system
            .as_ref()
            .and_then(|s| s["source"]["kind"].as_str().map(String::from)),
    }
}

const BAR_FILES: &str = "{spinner} [{elapsed_precise}] {wide_bar} {pos}/{len} files {msg}";
const BAR_BYTES: &str = "{spinner} [{elapsed_precise}] {wide_bar} {binary_bytes}/{binary_total_bytes} {binary_bytes_per_sec} ETA {eta} {msg}";

fn bar_style(template: &str) -> ProgressStyle {
    ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_bar())
}

fn collect(a: CollectArgs) -> u8 {
    let Some(out) = a.out.clone() else {
        return usage_error(
            "--out is required: choose the folder on the USB or network drive that receives the \
             package (e.g. --out E:\\triage). rv-triage has no default output folder, so nothing is \
             written to the machine being collected by mistake",
        );
    };
    let mut algos = Vec::new();
    for h in &a.hashes {
        match HashAlgo::parse(h) {
            Some(x) => algos.push(x),
            None => {
                return usage_error(&format!(
                    "unknown hash algorithm '{}': use md5, sha1, sha256, sha512, sha3-256 or blake3",
                    h
                ));
            }
        }
    }
    if let Err(e) = hash::validate_selection(&algos) {
        return usage_error(&e);
    }
    let langs = match i18n::parse_langs(&a.lang) {
        Ok(l) => l,
        Err(e) => return usage_error(&e),
    };
    let groups = match Group::parse_list(&a.groups) {
        Ok(g) => g,
        Err(e) => return usage_error(&format!("--groups: {}", e)),
    };
    let users: Vec<String> = a
        .users
        .iter()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();
    let source = match parse_source(&a.source) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || c.store(true, Ordering::SeqCst));

    let cfg = RunConfig {
        inputs: vec![],
        input_list: None,
        recursive: false,
        algorithms: algos,
        out_dir: out,
        langs,
        actor: a.actor.unwrap_or_else(rv_triage_core::env::os_user),
        case_id: a.case_id,
        frontend: "cli".into(),
        preamble: vec![],
        command_line: std::env::args().collect(),
        tool_name: TOOL_NAME.into(),
        tool_version: TOOL_VERSION.into(),
        jurisdiction: a.jurisdiction.clone(),
        tsa_url: if a.no_timestamp {
            None
        } else {
            Some(a.tsa_url.clone())
        },
        sign_password: a
            .sign_cert
            .as_ref()
            .and_then(|_| password(&a.sign_pass_env)),
        sign_cert: a.sign_cert.clone(),
        case_dir: None,
        evidence_ids: vec![],
        case_role: CASE_ROLE,
        collect: Some(CollectOptions {
            source,
            groups,
            users,
            allow_same_volume: a.allow_same_volume,
        }),
    };

    let bar = match a.progress {
        ProgressMode::Bar => {
            let b = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(8));
            b.set_style(bar_style(BAR_FILES));
            Some(b)
        }
        _ => None,
    };
    let jsonl = matches!(a.progress, ProgressMode::Jsonl);
    // A closed stdout (e.g. `| head`) must never abort a forensic run half-way: stop printing, keep working.
    let mut stdout_open = true;
    // The bar counts files while copying (the total size is unknown until every file is stat'ed), then
    // bytes while the package is re-read and the reports are written.
    let mut bytes_mode = false;
    let mut sink = |e: &Event| {
        if jsonl && stdout_open {
            let mut out = std::io::stdout().lock();
            stdout_open = writeln!(out, "{}", serde_json::to_string(e).unwrap_or_default())
                .and_then(|_| out.flush())
                .is_ok();
        }
        let Some(b) = &bar else {
            return;
        };
        match e {
            Event::Phase { phase, total } => {
                b.println(phase_line(phase, *total));
                if phase == "copy" {
                    b.set_length(*total);
                    b.set_position(0);
                }
                b.set_message(phase.clone());
            }
            Event::Artifact {
                group,
                source,
                status,
                code,
            } => {
                if let Some(l) = artifact_line(group, source, status, code) {
                    b.println(l);
                }
            }
            Event::RunStarted {
                total_bytes,
                total_items,
                ..
            } => {
                b.println(format!(
                    "phase: verify ({} packaged files re-read, reports)",
                    total_items
                ));
                if *total_bytes > 0 {
                    bytes_mode = true;
                    b.set_style(bar_style(BAR_BYTES));
                    b.set_length(*total_bytes);
                } else {
                    b.set_length(*total_items);
                }
                b.set_position(0);
                b.set_message(format!("0/{} files", total_items));
            }
            Event::Progress {
                done,
                total,
                bytes_done,
                bytes_total,
                ..
            } => {
                if *bytes_total == 0 || !bytes_mode {
                    // Copy phase: files done / total, bytes copied so far as the message.
                    b.set_length(*total);
                    b.set_position(*done);
                    b.set_message(format!("{} copied", human_bytes(*bytes_done)));
                } else {
                    b.set_position(*bytes_done);
                    b.set_message(format!("{}/{} files", done, total));
                }
            }
            Event::Error { path, message } => b.println(format!(
                "warning: {}: {}",
                path.as_deref().unwrap_or("-"),
                message
            )),
            Event::Cancelled { .. } => b.println("cancelled: writing partial reports..."),
            Event::Timestamp { status, reason, .. } if status != "ok" && status != "off" => b
                .println(format!(
                    "warning: timestamp pending ({}); run `rv-triage timestamp` later",
                    reason.as_deref().unwrap_or("-")
                )),
            _ => {}
        }
    };
    let result = run(&cfg, &mut sink, &cancel);
    if let Some(b) = &bar {
        b.finish_and_clear();
    }
    match result {
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
        Ok(s) => {
            if !jsonl {
                let package = s.report_dir.join("package");
                let f = package_facts(&package);
                let n = |x: Option<usize>| x.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
                let source = match (f.source_kind.as_deref(), f.elevated) {
                    (Some("live"), Some(true)) => "live (elevated: raw NTFS read)".to_string(),
                    (Some("live"), Some(false)) => {
                        "live (not elevated: locked files and other profiles not collected)"
                            .to_string()
                    }
                    (Some(k), _) => k.to_string(),
                    (None, _) => "-".to_string(),
                };
                let out = format!(
                    "{status}  run {id}\n  source: {source}\n  collected: {col}  not collected: {nc}  bytes: {bytes}  errors: {errors}  elapsed: {elapsed}\n  findings: high {h}, medium {m}, low {l}, info {i}\n  timestamp: {ts}\n  package: {package}\n  report: {report}\n  logs:   {logs}\n  audit head: {head}\n  next: in the lab, register the package with rv-hashinv: rv-hashinv scan -i \"{package}\" -r --case-dir <CASE>",
                    status = if s.cancelled {
                        "CANCELLED"
                    } else if s.high > 0 {
                        "DONE (high-severity findings)"
                    } else {
                        "DONE"
                    },
                    id = s.run_id,
                    col = n(f.collected),
                    nc = n(f.not_collected),
                    bytes = s.bytes,
                    errors = s.errors,
                    elapsed = rv_triage_core::time::human_duration(s.elapsed_ms),
                    h = s.high,
                    m = s.medium,
                    l = s.low,
                    i = s.info,
                    ts = format!(
                        "{} {}",
                        s.timestamp["status"].as_str().unwrap_or("off"),
                        s.timestamp["gen_time"].as_str().unwrap_or("")
                    )
                    .trim(),
                    package = package.display(),
                    report = s
                        .report_dir
                        .join(format!("statistics.{}.html", cfg.langs[0]))
                        .display(),
                    logs = s.log_dir.display(),
                    head = s.audit_head,
                );
                let _ = writeln!(std::io::stdout(), "{}", out);
            }
            if s.cancelled {
                EXIT_CANCELLED
            } else if s.high > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            }
        }
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", b)
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

fn password(env: &str) -> Option<String> {
    if let Ok(p) = std::env::var(env) {
        return Some(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // No echo: the password never appears on screen or in a terminal recording.
        return rpassword::prompt_password("Certificate password: ").ok();
    }
    None
}

fn timestamp(log: PathBuf, tsa_url: String, actor: Option<String>) -> u8 {
    let dir = if log.is_file() {
        log.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    } else {
        log
    };
    if !dir.join("audit.jsonl").is_file() {
        eprintln!(
            "error: no audit log at {}: nothing to timestamp",
            dir.join("audit.jsonl").display()
        );
        return EXIT_FINDINGS;
    }
    let mut audit_log =
        match audit::AuditLog::resume(&dir, &actor.unwrap_or_else(rv_triage_core::env::os_user)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: {}", e);
                return EXIT_FINDINGS;
            }
        };
    match trust::timestamp_head(&dir, audit_log.entries(), audit_log.head(), &tsa_url) {
        Ok(ts) => {
            if let Err(e) = audit_log.record("timestamp_obtained", Some(&ts.file), ts.to_json()) {
                eprintln!("error: {}", e);
                return EXIT_ERROR;
            }
            println!(
                "OK  timestamp {} by {} covers entry #{}",
                ts.gen_time, ts.tsa, ts.covers_seq
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn verify_log(log: PathBuf, tsa_ca: Option<PathBuf>) -> u8 {
    let path = if log.is_dir() {
        log.join("audit.jsonl")
    } else {
        log
    };
    let anchors = match tsa_ca.as_deref().map(trust::load_ca_bundle).transpose() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    let v = match verify::verify_log_with(&path, anchors.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    if v.problems.is_empty() {
        println!(
            "OK  {} entries, chain intact: {}",
            v.entries,
            path.display()
        );
        for t in &v.timestamps {
            println!("    {}", t);
        }
        println!("    {}", v.truncation);
    } else {
        println!("BROKEN  {}", path.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
    }
    if let Some(o) = &v.outputs {
        println!("    {}", o.summary());
        for s in o.skipped_lines() {
            println!("    {}", s);
        }
    }
    for w in &v.warnings {
        println!("  warning: {}", w);
    }
    if v.problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    }
}

fn verify_case(dir: PathBuf, rehash: bool) -> u8 {
    if !dir.join(case::CASE_FILE).is_file() {
        eprintln!(
            "error: {} is not a case folder (no {})",
            dir.display(),
            case::CASE_FILE
        );
        return EXIT_ERROR;
    }
    let mut v = case::verify_case(&dir);
    let rehashed = rehash.then(|| case::rehash_registry(&dir, &mut v));
    if v.problems.is_empty() {
        println!(
            "OK  case {}: {} case-log entries, {} registered items, {} runs verified: {}",
            v.case_id,
            v.entries,
            v.registry_items,
            v.runs,
            dir.display()
        );
        println!(
            "    outputs: {} verified of {} recorded by the runs' audit logs",
            v.outputs_verified, v.outputs_recorded
        );
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_OK
    } else {
        println!("BROKEN  case {}: {}", v.case_id, dir.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
        println!(
            "    outputs: {} verified of {} recorded by the runs' audit logs",
            v.outputs_verified, v.outputs_recorded
        );
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_FINDINGS
    }
}

fn self_test() -> u8 {
    let failed = hash::self_test();
    for (algo, _) in hash::KNOWN_ANSWERS {
        println!(
            "{:<9} {}",
            algo.name(),
            if failed.contains(&algo) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_ERROR
    }
}

/// The tool's self-description (`describe --json`, schema rakvor.describe/1; see schemas/describe.schema.json).
/// serde_json sorts the keys (no preserve_order feature), so the output is stable.
fn describe() -> serde_json::Value {
    serde_json::json!({
        "schema": "rakvor.describe/1",
        "tool": TOOL_NAME,
        "title": "RV Triage",
        "version": TOOL_VERSION,
        // Collection: it reads a live system (or an image or folder), not evidence files, and hands its package
        // to rv-hashinv for registration in the case folder.
        "role": "collection",
        "main_verb": MAIN_VERB,
        "accepts": {"extensions": [], "signatures": []},
        "case_formats": [case::SCHEMA_CASE],
        "log_formats": ["rakvor.audit/1"],
        "cli_exe": format!("{}.exe", TOOL_NAME),
        "gui_exe": format!("{}-gui.exe", TOOL_NAME),
        "exit_codes": {
            "0": "Completed; no high-severity finding.",
            "1": "Runtime error (source not found, output not writable or on the system volume, ...).",
            "2": "Usage error (--out missing, unknown option, group, algorithm or language).",
            "3": "Completed with at least one high-severity finding (partial read, copy mismatch, output on the system volume), or verify-log / verify-case found a problem.",
            "130": "Cancelled with Ctrl+C; partial package, reports and the cancellation are in the audit log."
        }
    })
}

/// Markdown of every command's long help, so docs/usage-cli.md can never drift from the binary.
fn docs_cli() -> String {
    let mut root = Cli::command().term_width(100);
    root.build();
    let mut out = String::from(
        "# Command-line reference\n\n<!-- Generated by `rv-triage docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
    );
    out.push_str("```mermaid\nflowchart LR\n  A[rv-triage] --> B[collect]\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n  A --> V[verify-case]\n  T --> E\n  B --> E[(logs/RUN-ID)]\n  B --> F[(reports/RUN-ID/package)]\n  F -. rv-hashinv .-> K[(CASE folder)]\n  V --> K\n  C --> E\n```\n\n");
    out.push_str(&format!(
        "## rv-triage\n\n```text\n{}\n```\n\n",
        root.render_long_help().to_string().trim_end()
    ));
    let names: Vec<String> = root
        .get_subcommands()
        // `describe` is hidden from the command list but documented (RV Hub reads it).
        .filter(|c| (!c.is_hide_set() || c.get_name() == "describe") && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("subcommand");
        let mut sub = sub.clone().bin_name(format!("rv-triage {}", name));
        out.push_str(&format!(
            "## rv-triage {}\n\n```text\n{}\n```\n\n",
            name,
            sub.render_long_help().to_string().trim_end()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_lines_only_for_what_needs_attention() {
        assert_eq!(
            artifact_line("hives", "C:\\x", "collected", "COLLECTED_RAW"),
            None
        );
        assert_eq!(artifact_line("hives", "C:\\x", "collected", ""), None);
        assert_eq!(
            artifact_line("hives", "C:\\x", "not_collected", "NOT_COLLECTED_NO_ADMIN").unwrap(),
            "not collected: [hives] C:\\x (NOT_COLLECTED_NO_ADMIN)"
        );
        assert_eq!(
            artifact_line("evtx", "C:\\y", "collected", "CHANGED_DURING_COPY").unwrap(),
            "warning: [evtx] C:\\y: CHANGED_DURING_COPY"
        );
    }

    #[test]
    fn phase_lines() {
        assert_eq!(phase_line("copy", 412), "phase: copy (412 files)");
        assert_eq!(phase_line("preflight", 0), "phase: preflight");
        assert_eq!(phase_line("volatile", 4), "phase: volatile (4 steps)");
    }

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn source_live_or_existing_path() {
        assert_eq!(parse_source("LIVE").unwrap(), SourceSpec::Live);
        assert!(parse_source("does/not/exist").is_err());
        assert!(matches!(
            parse_source(env!("CARGO_MANIFEST_DIR")).unwrap(),
            SourceSpec::Directory(_)
        ));
    }
}
