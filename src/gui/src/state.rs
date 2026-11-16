//! Everything the window shows and every rule it enforces, without any drawing code.
//! Kept separate from `app.rs` so it can be unit-tested headless (CI has no display).
//!
//! The window is a collection screen: source (live system, volume image, folder), artifact groups, users
//! filter, output folder and the "system volume" override map 1:1 onto [`CollectOptions`]; the hash, report,
//! examiner, case id and trust settings are the template's. Every setting change is recorded with `at_utc`
//! and handed to the core as an audit preamble entry when the run starts.

use rv_triage_core::collect::{CollectOptions, Group, SourceSpec, host, phase::PACKAGE_DIR};
use rv_triage_core::time::human_duration;
use rv_triage_core::{CASE_ROLE, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, hash, i18n};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub elapsed_ms: u64,
    pub eta_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub items: u64,
    pub errors: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub report: PathBuf,
    pub log_dir: PathBuf,
    /// `<out>/reports/<RUN-ID>/package`.
    pub package: PathBuf,
}

/// Where the artifacts are read from (the source picker).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Live,
    Image,
    Directory,
}

impl SourceKind {
    pub const ALL: [SourceKind; 3] = [SourceKind::Live, SourceKind::Image, SourceKind::Directory];

    /// Same words as [`SourceSpec::kind`].
    pub fn name(&self) -> &'static str {
        match self {
            SourceKind::Live => "live",
            SourceKind::Image => "image",
            SourceKind::Directory => "directory",
        }
    }
}

/// The collection step the core reports (`Event::Phase`), plus `verify` (re-reading the package).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectStep {
    /// preflight | volatile | copy | verify
    pub name: String,
    /// Steps or files in the step (0 when unknown).
    pub total: u64,
}

/// One row of the results table (`Event::Artifact`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRow {
    pub group: String,
    pub source: String,
    /// collected | not_collected
    pub status: String,
    /// Most severe finding code (may be empty).
    pub code: String,
}

impl ArtifactRow {
    pub fn collected(&self) -> bool {
        self.status == "collected"
    }
}

pub const LANG_CHOICES: [(&str, &str); 4] = [
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("all", "All three (EN + ES + FR)"),
];

/// Text fields are edited freely and audited when they are committed (focus lost, Browse, Start): the
/// values last written to the audit trail.
#[derive(Clone, Debug, Default)]
struct Committed {
    source_path: String,
    users: String,
    out_dir: String,
    actor: String,
    case_id: String,
}

#[derive(Clone, Debug)]
pub struct GuiState {
    /// Whether this process runs as administrator (`host::is_elevated()` at start).
    pub elevated: bool,
    pub source_kind: SourceKind,
    /// Image file or folder (unused for the live system).
    pub source_path: String,
    /// Ticked groups (volatile stays ticked but is dropped for a non-live source: see `effective_groups`).
    pub groups: Vec<Group>,
    /// Users filter as typed: comma-separated profile folder names, empty = every profile.
    pub users: String,
    /// Allow writing the package on the system volume of the machine being collected (off by default).
    pub allow_same_volume: bool,
    pub selected: Vec<HashAlgo>,
    pub lang: String,
    /// Required: no default (a USB stick or an examiner drive must be chosen deliberately).
    pub out_dir: String,
    pub actor: String,
    pub case_id: String,
    pub phase: Phase,
    pub progress: Progress,
    pub current_item: String,
    pub warnings: Vec<String>,
    pub outcome: Option<Outcome>,
    /// User actions recorded before the run; handed to the core as audit preamble entries.
    pub ui_actions: Vec<(String, Value)>,
    /// Interface language (en/es/fr), independent from the report language.
    pub ui_lang: String,
    pub jurisdiction: String,
    pub timestamp: bool,
    pub tsa_url: String,
    pub sign_cert: String,
    /// Kept in memory only; never logged.
    pub sign_password: String,
    /// Current collection step of the running (or last) run.
    pub step: Option<CollectStep>,
    /// Results table, in the order the core reported them.
    pub artifacts: Vec<ArtifactRow>,
    /// Results table filter.
    pub not_collected_only: bool,
    /// Files finished in the copy step (collected or not).
    copy_done: u64,
    committed: Committed,
}

impl Default for GuiState {
    fn default() -> Self {
        let actor = rv_triage_core::env::os_user();
        GuiState {
            elevated: host::is_elevated(),
            source_kind: SourceKind::Live,
            source_path: String::new(),
            groups: Group::ALL.to_vec(),
            users: String::new(),
            allow_same_volume: false,
            selected: vec![HashAlgo::Sha256],
            lang: "en".into(),
            out_dir: String::new(),
            actor: actor.clone(),
            case_id: String::new(),
            phase: Phase::Idle,
            progress: Progress::default(),
            current_item: String::new(),
            warnings: vec![],
            outcome: None,
            ui_actions: vec![],
            ui_lang: "en".into(),
            jurisdiction: "co".into(),
            timestamp: true,
            tsa_url: rv_triage_core::trust::DEFAULT_TSA.into(),
            sign_cert: String::new(),
            sign_password: String::new(),
            step: None,
            artifacts: vec![],
            not_collected_only: false,
            copy_done: 0,
            committed: Committed {
                actor,
                ..Default::default()
            },
        }
    }
}

fn clean_path(p: &str) -> String {
    p.trim().trim_matches('"').trim().to_string()
}

/// `"ana, Bob ,,ana"` → `["ana", "Bob"]` (trimmed, empty parts dropped, duplicates removed case-insensitively).
pub fn split_users(s: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for u in s.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(u)) {
            out.push(u.to_string());
        }
    }
    out
}

/// `1536` → `1.5 KB` (base 1024, one decimal).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", n)
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

impl GuiState {
    /// Records a user action with the time it happened (written to the audit log when the run starts).
    fn note(&mut self, action: &str, mut details: Value) {
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_triage_core::time::utc_now()));
        }
        self.ui_actions.push((action.to_string(), details));
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    // ---- elevation -------------------------------------------------------------------------------------

    /// "Restart as administrator" clicked: recorded here (the window closes if the relaunch starts) and the
    /// time is handed to the elevated window, which records `ui_restarted_as_admin` in its own trail.
    pub fn request_elevation(&mut self) -> String {
        let at = rv_triage_core::time::utc_now();
        self.note(
            "ui_restart_as_admin_clicked",
            json!({"elevated": self.elevated, "pending_actions_discarded": self.ui_actions.len()}),
        );
        at
    }

    /// The relaunch did not start (UAC prompt declined, not Windows): the window stays open.
    pub fn elevation_failed(&mut self, error: &str) {
        self.note("ui_restart_as_admin_failed", json!({"error": error}));
    }

    /// This window was started by "Restart as administrator" in a previous window.
    pub fn restarted_after_request(&mut self, requested_at_utc: &str) {
        self.note(
            "ui_restarted_as_admin",
            json!({"requested_at_utc": requested_at_utc, "elevated": self.elevated}),
        );
    }

    // ---- source ----------------------------------------------------------------------------------------

    pub fn volatile_available(&self) -> bool {
        self.source_kind == SourceKind::Live
    }

    fn note_source(&mut self) {
        let path = if self.source_kind == SourceKind::Live {
            Value::Null
        } else {
            json!(self.source_path)
        };
        self.note(
            "ui_source_changed",
            json!({"kind": self.source_kind.name(), "path": path}),
        );
    }

    /// Radio button: the path typed for image/folder is kept when switching kinds.
    pub fn set_source_kind(&mut self, k: SourceKind) {
        if self.source_kind != k {
            self.source_kind = k;
            self.source_path = clean_path(&self.source_path);
            self.committed.source_path = self.source_path.clone();
            self.note_source();
        }
    }

    /// From a file/folder dialog, a launch argument or a drop: kind and path at once.
    pub fn set_source(&mut self, k: SourceKind, path: &str) {
        let path = if k == SourceKind::Live {
            self.source_path.clone()
        } else {
            clean_path(path)
        };
        if self.source_kind != k || self.source_path != path {
            self.source_kind = k;
            self.source_path = path;
            self.committed.source_path = self.source_path.clone();
            self.note_source();
        }
    }

    /// A path given to the exe or dropped on the window: a folder is a folder source, anything else an image.
    pub fn set_source_from_path(&mut self, p: &Path) {
        let k = if p.is_dir() {
            SourceKind::Directory
        } else {
            SourceKind::Image
        };
        self.set_source(k, &p.display().to_string());
    }

    pub fn source_spec(&self) -> Result<SourceSpec, String> {
        let p = clean_path(&self.source_path);
        match self.source_kind {
            SourceKind::Live => Ok(SourceSpec::Live),
            _ if p.is_empty() => Err(self.tr("err_source_path")),
            SourceKind::Image => Ok(SourceSpec::Image(PathBuf::from(p))),
            SourceKind::Directory => Ok(SourceSpec::Directory(PathBuf::from(p))),
        }
    }

    // ---- groups, users, output -------------------------------------------------------------------------

    /// Volatile data exists only on the running system: its checkbox is disabled for an image or a folder.
    pub fn can_toggle_group(&self, g: Group) -> bool {
        !self.is_running() && (g != Group::Volatile || self.volatile_available())
    }

    pub fn toggle_group(&mut self, g: Group) {
        if !self.can_toggle_group(g) {
            return;
        }
        if let Some(i) = self.groups.iter().position(|x| *x == g) {
            self.groups.remove(i);
        } else {
            self.groups.push(g);
            self.groups.sort();
        }
        let names: Vec<&str> = self.groups.iter().map(|g| g.name()).collect();
        self.note("ui_groups_changed", json!({"groups": names}));
    }

    /// What is collected: the ticked groups, without volatile for a non-live source.
    pub fn effective_groups(&self) -> Vec<Group> {
        self.groups
            .iter()
            .copied()
            .filter(|g| *g != Group::Volatile || self.volatile_available())
            .collect()
    }

    pub fn users_list(&self) -> Vec<String> {
        split_users(&self.users)
    }

    pub fn set_allow_same_volume(&mut self, on: bool) {
        if self.allow_same_volume != on {
            self.allow_same_volume = on;
            self.note("ui_allow_system_volume_changed", json!({"allowed": on}));
        }
    }

    pub fn set_out_dir(&mut self, path: &str) {
        self.out_dir = clean_path(path);
        self.commit_entries();
    }

    /// Audits every text field whose value changed since it was last committed (called when a field loses
    /// focus and before a run starts).
    pub fn commit_entries(&mut self) {
        let source = clean_path(&self.source_path);
        if source != self.committed.source_path {
            self.source_path = source.clone();
            self.committed.source_path = source;
            self.note_source();
        }
        if self.users != self.committed.users {
            self.committed.users = self.users.clone();
            let users = self.users_list();
            self.note("ui_users_changed", json!({"users": users}));
        }
        let out = clean_path(&self.out_dir);
        if out != self.committed.out_dir {
            self.out_dir = out.clone();
            self.committed.out_dir = out.clone();
            self.note("ui_output_folder_changed", json!({"path": out}));
        }
        if self.actor != self.committed.actor {
            self.committed.actor = self.actor.clone();
            self.note(
                "ui_examiner_changed",
                json!({"examiner": self.actor.trim()}),
            );
        }
        if self.case_id != self.committed.case_id {
            self.committed.case_id = self.case_id.clone();
            self.note(
                "ui_case_id_changed",
                json!({"case_id": self.case_id.trim()}),
            );
        }
    }

    pub fn set_not_collected_only(&mut self, on: bool) {
        if self.not_collected_only != on {
            self.not_collected_only = on;
            self.note(
                "ui_result_filter_changed",
                json!({"not_collected_only": on}),
            );
        }
    }

    // ---- template settings -----------------------------------------------------------------------------

    /// A checkbox is clickable if it can be unticked (more than one ticked) or ticked (fewer than two ticked).
    pub fn can_toggle(&self, a: HashAlgo) -> bool {
        if self.selected.contains(&a) {
            self.selected.len() > 1
        } else {
            self.selected.len() < HashAlgo::MAX_SELECTED
        }
    }

    pub fn toggle_algo(&mut self, a: HashAlgo) -> Result<(), String> {
        if !self.can_toggle(a) {
            return Err(if self.selected.contains(&a) {
                "At least one hash algorithm is required.".into()
            } else {
                format!(
                    "At most {} hash algorithms can be selected.",
                    HashAlgo::MAX_SELECTED
                )
            });
        }
        if let Some(i) = self.selected.iter().position(|x| *x == a) {
            self.selected.remove(i);
        } else {
            self.selected.push(a);
        }
        self.note(
            "ui_hash_selection_changed",
            json!({"algorithms": self.selected}),
        );
        Ok(())
    }

    pub fn set_lang(&mut self, l: &str) {
        if self.lang != l {
            self.lang = l.to_string();
            self.note("ui_language_changed", json!({"lang": l}));
        }
    }

    /// GUI text in the interface language.
    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang != l && ["en", "es", "fr"].contains(&l) {
            self.ui_lang = l.to_string();
            self.note("ui_interface_language_changed", json!({"ui_lang": l}));
        }
    }

    pub fn set_jurisdiction(&mut self, j: &str) {
        if self.jurisdiction != j && (j == "co" || j == "fr") {
            self.jurisdiction = j.to_string();
            self.note("ui_jurisdiction_changed", json!({"jurisdiction": j}));
        }
    }

    pub fn set_timestamp(&mut self, on: bool, url: &str) {
        let url = url.trim().to_string();
        if self.timestamp != on || self.tsa_url != url {
            self.timestamp = on;
            self.tsa_url = url.clone();
            self.note(
                "ui_timestamp_changed",
                json!({"enabled": on, "tsa_url": url}),
            );
        }
    }

    pub fn set_sign_cert(&mut self, path: &str) {
        let path = clean_path(path);
        if self.sign_cert != path {
            self.sign_cert = path.clone();
            self.note(
                "ui_signing_certificate_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// A launch argument that was ignored, recorded in the audit log.
    pub fn note_launch_problem(&mut self, problem: &str) {
        self.note("ui_launch_argument_ignored", json!({"problem": problem}));
    }

    // ---- run -------------------------------------------------------------------------------------------

    /// Why Start is disabled (interface-language text), `None` when it can start.
    pub fn start_blocker(&self) -> Option<String> {
        if self.is_running() {
            Some(self.tr("err_running"))
        } else if clean_path(&self.out_dir).is_empty() {
            Some(self.tr("err_out_dir"))
        } else if self.source_kind != SourceKind::Live && clean_path(&self.source_path).is_empty() {
            Some(self.tr("err_source_path"))
        } else if self.effective_groups().is_empty() {
            Some(self.tr("err_groups"))
        } else {
            None
        }
    }

    pub fn can_start(&self) -> bool {
        self.start_blocker().is_none()
    }

    /// The domain options, 1:1 from the settings.
    pub fn collect_options(&self) -> Result<CollectOptions, String> {
        let groups = self.effective_groups();
        if groups.is_empty() {
            return Err(self.tr("err_groups"));
        }
        Ok(CollectOptions {
            source: self.source_spec()?,
            groups,
            users: self.users_list(),
            allow_same_volume: self.allow_same_volume,
        })
    }

    /// Builds the run configuration; pending text edits are committed first, and the recorded UI actions
    /// become audit preamble entries.
    pub fn to_config(&mut self) -> Result<RunConfig, String> {
        self.commit_entries();
        if let Some(why) = self.start_blocker() {
            return Err(why);
        }
        let opts = self.collect_options()?;
        match &opts.source {
            SourceSpec::Image(p) if !p.is_file() => {
                return Err(format!("{}: {}", self.tr("err_image_missing"), p.display()));
            }
            SourceSpec::Directory(p) if !p.is_dir() => {
                return Err(format!(
                    "{}: {}",
                    self.tr("err_folder_missing"),
                    p.display()
                ));
            }
            _ => {}
        }
        hash::validate_selection(&self.selected)?;
        let case_id = Some(self.case_id.trim().to_string()).filter(|s| !s.is_empty());
        let langs = i18n::parse_langs(&self.lang)?;
        if !self.sign_cert.is_empty() && !Path::new(&self.sign_cert).is_file() {
            return Err(format!("Signing certificate not found: {}", self.sign_cert));
        }
        let group_names: Vec<&str> = opts.groups.iter().map(|g| g.name()).collect();
        let source_path = match &opts.source {
            SourceSpec::Live => Value::Null,
            SourceSpec::Image(p) | SourceSpec::Directory(p) => json!(p.display().to_string()),
        };
        let mut preamble = self.ui_actions.clone();
        preamble.push(("ui_start_clicked".into(), json!({"algorithms": self.selected, "lang": self.lang,
            "source": opts.source.kind(), "source_path": source_path, "groups": group_names, "users": opts.users,
            "allow_same_volume": opts.allow_same_volume, "elevated": self.elevated, "out_dir": self.out_dir,
            "jurisdiction": self.jurisdiction, "timestamp": self.timestamp, "pdf_signing": !self.sign_cert.is_empty(),
            "at_utc": rv_triage_core::time::utc_now()})));
        let settings = vec![
            format!("{} collect (gui)", TOOL_NAME),
            format!(
                "source={}",
                match &opts.source {
                    SourceSpec::Live => "live".to_string(),
                    SourceSpec::Image(p) | SourceSpec::Directory(p) => p.display().to_string(),
                }
            ),
            format!("source_kind={}", opts.source.kind()),
            format!("groups={}", group_names.join(",")),
            format!(
                "users={}",
                if opts.users.is_empty() {
                    "all".to_string()
                } else {
                    opts.users.join(",")
                }
            ),
            format!("allow_same_volume={}", opts.allow_same_volume),
            format!(
                "hash={}",
                self.selected
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!("lang={}", self.lang),
            format!("out={}", self.out_dir),
            format!("jurisdiction={}", self.jurisdiction),
            format!(
                "tsa={}",
                if self.timestamp {
                    self.tsa_url.as_str()
                } else {
                    "off"
                }
            ),
            format!(
                "sign_cert={}",
                if self.sign_cert.is_empty() {
                    "none"
                } else {
                    self.sign_cert.as_str()
                }
            ),
        ];
        Ok(RunConfig {
            inputs: vec![],
            input_list: None,
            recursive: true,
            algorithms: self.selected.clone(),
            out_dir: PathBuf::from(&self.out_dir),
            langs,
            actor: if self.actor.trim().is_empty() {
                rv_triage_core::env::os_user()
            } else {
                self.actor.trim().to_string()
            },
            case_id,
            frontend: "gui".into(),
            preamble,
            command_line: settings,
            tool_name: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            jurisdiction: self.jurisdiction.clone(),
            tsa_url: if self.timestamp {
                Some(self.tsa_url.clone())
            } else {
                None
            },
            sign_cert: if self.sign_cert.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.sign_cert))
            },
            sign_password: if self.sign_password.is_empty() {
                None
            } else {
                Some(self.sign_password.clone())
            },
            case_dir: None,
            evidence_ids: vec![],
            case_role: CASE_ROLE,
            collect: Some(opts),
        })
    }

    pub fn start(&mut self) {
        self.phase = Phase::Running;
        self.progress = Progress::default();
        self.current_item.clear();
        self.warnings.clear();
        self.outcome = None;
        self.step = None;
        self.artifacts.clear();
        self.copy_done = 0;
        // Recorded actions now belong to this run's audit log.
        self.ui_actions.clear();
    }

    fn in_step(&self, name: &str) -> bool {
        self.step.as_ref().is_some_and(|s| s.name == name)
    }

    pub fn apply(&mut self, e: &Event) {
        match e {
            Event::Phase { phase, total } => {
                self.step = Some(CollectStep {
                    name: phase.clone(),
                    total: *total,
                });
                if phase == "copy" {
                    self.copy_done = 0;
                    self.progress.done = 0;
                    self.progress.total = *total;
                    self.progress.bytes_done = 0;
                    self.progress.bytes_total = 0;
                    self.progress.eta_ms = None;
                }
            }
            Event::Artifact {
                group,
                source,
                status,
                code,
            } => {
                self.artifacts.push(ArtifactRow {
                    group: group.clone(),
                    source: source.clone(),
                    status: status.clone(),
                    code: code.clone(),
                });
                if self.in_step("copy") {
                    self.copy_done += 1;
                    self.progress.done = self.copy_done.max(self.progress.done);
                    self.current_item = source.clone();
                }
            }
            Event::RunStarted {
                total_items,
                total_bytes,
                ..
            } => {
                // After the collection the core re-reads every packaged file and compares the digests.
                if self.step.is_some() {
                    self.step = Some(CollectStep {
                        name: "verify".into(),
                        total: *total_items,
                    });
                }
                self.progress.done = 0;
                self.progress.bytes_done = 0;
                self.progress.eta_ms = None;
                self.progress.total = *total_items;
                self.progress.bytes_total = *total_bytes;
            }
            Event::ItemStarted { path, .. } => self.current_item = path.clone(),
            Event::Progress {
                done,
                total,
                bytes_done,
                bytes_total,
                elapsed_ms,
                eta_ms,
            } => {
                if self.in_step("copy") {
                    // bytes_total is unknown while copying: files are the measure, no time estimate.
                    self.progress.done = self.copy_done.max(*done);
                    self.progress.total = *total;
                    self.progress.bytes_done = *bytes_done;
                    self.progress.bytes_total = 0;
                    self.progress.elapsed_ms = *elapsed_ms;
                    self.progress.eta_ms = None;
                } else {
                    self.progress = Progress {
                        done: *done,
                        total: *total,
                        bytes_done: *bytes_done,
                        bytes_total: *bytes_total,
                        elapsed_ms: *elapsed_ms,
                        eta_ms: *eta_ms,
                    };
                }
            }
            Event::Error { path, message } => {
                self.warnings
                    .push(format!("{}: {}", path.as_deref().unwrap_or("-"), message))
            }
            Event::RunFinished {
                items,
                errors,
                high,
                medium,
                low,
                info,
                report_dir,
                log_dir,
                cancelled,
                elapsed_ms,
                ..
            } => {
                self.progress.elapsed_ms = *elapsed_ms;
                self.progress.eta_ms = None;
                let lang = if self.lang == "all" {
                    "en".to_string()
                } else {
                    self.lang.clone()
                };
                self.outcome = Some(Outcome {
                    items: *items,
                    errors: *errors,
                    high: *high,
                    medium: *medium,
                    low: *low,
                    info: *info,
                    report: PathBuf::from(report_dir).join(format!("statistics.{}.html", lang)),
                    log_dir: PathBuf::from(log_dir),
                    package: PathBuf::from(report_dir).join(PACKAGE_DIR),
                });
                self.phase = if *cancelled {
                    Phase::Cancelled
                } else {
                    Phase::Finished
                };
                self.current_item.clear();
            }
            _ => {}
        }
    }

    pub fn fail(&mut self, msg: String) {
        self.phase = Phase::Failed(msg);
    }

    /// 0.0..=1.0, by bytes (or by files when the byte total is unknown or zero).
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if matches!(self.phase, Phase::Finished) {
            1.0
        } else if p.bytes_total > 0 {
            (p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32
        } else if p.total > 0 {
            (p.done as f64 / p.total as f64).clamp(0.0, 1.0) as f32
        } else {
            0.0
        }
    }

    /// `live_elapsed_ms` is measured by the window clock so the timer keeps moving between events. No
    /// estimate is shown while collecting (the size of what is left is unknown).
    pub fn timing_text(&self, live_elapsed_ms: Option<u64>) -> String {
        let elapsed = live_elapsed_ms
            .unwrap_or(self.progress.elapsed_ms)
            .max(self.progress.elapsed_ms);
        let collecting = self.step.as_ref().is_some_and(|s| s.name != "verify");
        let eta = match self.progress.eta_ms {
            Some(ms) if self.is_running() && !collecting => human_duration(ms),
            _ => "\u{2014}".into(),
        };
        format!(
            "{}: {}   \u{00B7}   {}: {}",
            self.tr("elapsed"),
            human_duration(elapsed),
            self.tr("remaining"),
            eta
        )
    }

    /// "Step: Copying files (12 / 40)" for the current collection step, empty before the first one.
    pub fn step_text(&self) -> String {
        let Some(s) = &self.step else {
            return String::new();
        };
        let label = self.tr(&format!("step_{}", s.name));
        let detail = match s.name.as_str() {
            "copy" | "verify" => format!(" ({} / {})", self.progress.done, s.total),
            _ => String::new(),
        };
        format!("{}: {}{}", self.tr("step"), label, detail)
    }

    pub fn progress_text(&self) -> String {
        let p = &self.progress;
        if self.is_running() && (self.in_step("preflight") || self.in_step("volatile")) {
            return self.step_text();
        }
        let mut s = format!(
            "{} / {} {}  \u{00B7}  {:.0}%",
            p.done,
            p.total,
            self.tr("files"),
            self.fraction() * 100.0
        );
        if self.in_step("copy") && p.bytes_done > 0 {
            s.push_str(&format!(
                "  \u{00B7}  {} {}",
                human_bytes(p.bytes_done),
                self.tr("read")
            ));
        }
        s
    }

    // ---- results ---------------------------------------------------------------------------------------

    /// (collected, not collected) rows so far.
    pub fn counts(&self) -> (usize, usize) {
        let c = self.artifacts.iter().filter(|a| a.collected()).count();
        (c, self.artifacts.len() - c)
    }

    pub fn visible_rows(&self) -> Vec<&ArtifactRow> {
        self.artifacts
            .iter()
            .filter(|a| !self.not_collected_only || !a.collected())
            .collect()
    }

    pub fn group_label(&self, group: &str) -> String {
        self.tr(&format!("group_{}", group))
    }

    pub fn status_label(&self, status: &str) -> String {
        self.tr(&format!("status_{}", status))
    }

    /// `COLLECTED_RAW — Copied by raw NTFS read` (finding title from the core catalogue), `—` without a code.
    pub fn finding_text(&self, code: &str) -> String {
        if code.is_empty() {
            return "\u{2014}".into();
        }
        let (title, _, _) = i18n::catalog(&self.ui_lang).finding(code, &BTreeMap::new());
        format!("{} \u{2014} {}", code, title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(s: &GuiState) -> Vec<&str> {
        s.ui_actions.iter().map(|(a, _)| a.as_str()).collect()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rv-triage-gui-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A folder laid out like a Windows volume root, with magic bytes only (no real data).
    fn windows_like(dir: &Path) {
        for (rel, body) in [
            ("Windows/System32/config/SYSTEM", &b"regf-synthetic"[..]),
            ("Windows/System32/winevt/Logs/Security.evtx", b"ElfFile\0"),
            ("Windows/Prefetch/CMD.EXE-0BD30981.pf", b"MAM\x04"),
            (
                "Windows/System32/Tasks/Updater",
                b"<?xml version=\"1.0\"?><Task/>",
            ),
            ("Users/alex.demo/NTUSER.DAT", b"regf-alex"),
            ("Users/sam.demo/NTUSER.DAT", b"regf-sam"),
        ] {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
    }

    #[test]
    fn at_most_two_and_at_least_one_algorithm() {
        let mut s = GuiState::default();
        assert_eq!(s.selected, vec![HashAlgo::Sha256]);
        assert!(
            !s.can_toggle(HashAlgo::Sha256),
            "cannot untick the last one"
        );
        assert!(s.toggle_algo(HashAlgo::Sha256).is_err());
        s.toggle_algo(HashAlgo::Md5).unwrap();
        assert!(
            !s.can_toggle(HashAlgo::Blake3),
            "third checkbox is disabled"
        );
        assert!(s.toggle_algo(HashAlgo::Blake3).is_err());
        assert!(s.can_toggle(HashAlgo::Sha256));
        s.toggle_algo(HashAlgo::Sha256).unwrap();
        assert_eq!(s.selected, vec![HashAlgo::Md5]);
    }

    #[test]
    fn defaults_map_onto_collect_options() {
        let s = GuiState::default();
        let o = s.collect_options().unwrap();
        assert_eq!(
            o,
            CollectOptions::default(),
            "live, every group, every user"
        );
        assert!(!o.allow_same_volume && !s.allow_same_volume);
        assert_eq!(s.source_kind, SourceKind::Live);
        assert!(s.out_dir.is_empty(), "no output folder until one is chosen");
    }

    #[test]
    fn source_variants_map_onto_source_spec() {
        let mut s = GuiState::default();
        assert_eq!(s.source_spec().unwrap(), SourceSpec::Live);
        s.set_source_kind(SourceKind::Image);
        assert!(s.source_spec().is_err(), "an image needs a path");
        s.set_source(SourceKind::Image, "\"E:\\images\\disk.dd\"");
        assert_eq!(
            s.source_spec().unwrap(),
            SourceSpec::Image(PathBuf::from("E:\\images\\disk.dd"))
        );
        s.set_source(SourceKind::Directory, " F:\\mounted ");
        assert_eq!(
            s.collect_options().unwrap().source,
            SourceSpec::Directory(PathBuf::from("F:\\mounted"))
        );
        s.set_source_kind(SourceKind::Live);
        assert_eq!(s.source_spec().unwrap(), SourceSpec::Live);
        let d = tmp("srcpath");
        s.set_source_from_path(&d);
        assert_eq!(s.source_kind, SourceKind::Directory);
        s.set_source_from_path(&d.join("disk.img"));
        assert_eq!(s.source_kind, SourceKind::Image);
        let kinds: Vec<&str> = s
            .ui_actions
            .iter()
            .filter(|(a, _)| a == "ui_source_changed")
            .map(|(_, d)| d["kind"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            ["image", "image", "directory", "live", "directory", "image"]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn groups_users_and_system_volume_map_one_to_one() {
        let mut s = GuiState::default();
        s.toggle_group(Group::Browsers);
        s.toggle_group(Group::Prefetch);
        s.users = " alex.demo, ,SAM.demo ,alex.demo".into();
        s.set_allow_same_volume(true);
        let o = s.collect_options().unwrap();
        assert_eq!(
            o.groups,
            Group::parse_list("volatile,evtx,hives,tasks").unwrap()
        );
        assert_eq!(o.users, vec!["alex.demo", "SAM.demo"]);
        assert!(o.allow_same_volume);
        s.toggle_group(Group::Prefetch);
        assert!(
            s.collect_options()
                .unwrap()
                .groups
                .contains(&Group::Prefetch)
        );
        s.users.clear();
        assert!(
            s.collect_options().unwrap().users.is_empty(),
            "empty = every profile"
        );
        assert_eq!(split_users("a,b"), ["a", "b"]);
    }

    #[test]
    fn volatile_is_disabled_and_dropped_for_non_live_sources() {
        let mut s = GuiState::default();
        assert!(s.can_toggle_group(Group::Volatile));
        s.set_source(SourceKind::Directory, "F:\\mounted");
        assert!(!s.can_toggle_group(Group::Volatile));
        s.toggle_group(Group::Volatile);
        assert!(
            s.groups.contains(&Group::Volatile),
            "disabled checkbox ignores clicks"
        );
        let o = s.collect_options().unwrap();
        assert!(!o.groups.contains(&Group::Volatile));
        assert_eq!(o.groups.len(), 5);
        s.set_source(SourceKind::Image, "disk.dd");
        assert!(
            !s.collect_options()
                .unwrap()
                .groups
                .contains(&Group::Volatile)
        );
        s.set_source_kind(SourceKind::Live);
        assert!(
            s.collect_options()
                .unwrap()
                .groups
                .contains(&Group::Volatile)
        );
        // Only volatile ticked and a folder source: nothing to collect, Start is disabled.
        let mut s = GuiState {
            out_dir: "E:\\out".into(),
            ..Default::default()
        };
        for g in [
            Group::Evtx,
            Group::Hives,
            Group::Prefetch,
            Group::Browsers,
            Group::Tasks,
        ] {
            s.toggle_group(g);
        }
        assert!(s.can_start());
        s.set_source(SourceKind::Directory, "F:\\mounted");
        assert!(!s.can_start() && s.collect_options().is_err());
    }

    #[test]
    fn start_is_disabled_without_an_output_folder() {
        let mut s = GuiState::default();
        assert!(!s.can_start());
        assert_eq!(s.start_blocker(), Some(s.tr("err_out_dir")));
        assert!(s.to_config().is_err());
        s.out_dir = "   ".into();
        assert!(!s.can_start());
        s.out_dir = "E:\\rv-out".into();
        assert!(s.can_start(), "live source, every group, an output folder");
        s.set_source_kind(SourceKind::Directory);
        assert!(!s.can_start(), "a folder source needs its path");
        s.phase = Phase::Running;
        s.set_source_kind(SourceKind::Live);
        assert!(!s.can_start(), "not while running");
    }

    #[test]
    fn every_setting_change_is_an_audited_ui_action_with_time() {
        let mut s = GuiState::default();
        s.set_source(SourceKind::Directory, "F:\\mounted");
        s.toggle_group(Group::Tasks);
        s.users = "alex.demo".into();
        s.commit_entries();
        s.set_allow_same_volume(true);
        s.set_out_dir("E:\\rv-out");
        s.actor = "Examiner Demo".into();
        s.case_id = "CASE-DEMO-1".into();
        s.commit_entries();
        s.commit_entries(); // nothing changed: nothing recorded
        s.toggle_algo(HashAlgo::Blake3).unwrap();
        s.set_lang("es");
        s.set_ui_lang("fr");
        s.set_jurisdiction("fr");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("cert.p12");
        s.set_not_collected_only(true);
        s.request_elevation();
        s.elevation_failed("cancelled by the user");
        s.restarted_after_request("2026-11-15T10:00:00Z");
        assert_eq!(
            actions(&s),
            [
                "ui_source_changed",
                "ui_groups_changed",
                "ui_users_changed",
                "ui_allow_system_volume_changed",
                "ui_output_folder_changed",
                "ui_examiner_changed",
                "ui_case_id_changed",
                "ui_hash_selection_changed",
                "ui_language_changed",
                "ui_interface_language_changed",
                "ui_jurisdiction_changed",
                "ui_timestamp_changed",
                "ui_signing_certificate_changed",
                "ui_result_filter_changed",
                "ui_restart_as_admin_clicked",
                "ui_restart_as_admin_failed",
                "ui_restarted_as_admin",
            ]
        );
        for (a, d) in &s.ui_actions {
            assert!(a.starts_with("ui_"));
            assert!(
                d["at_utc"].as_str().is_some_and(|t| t.ends_with('Z')),
                "{} has no at_utc",
                a
            );
        }
        assert_eq!(s.ui_actions[2].1["users"], json!(["alex.demo"]));
        assert_eq!(
            s.ui_actions[16].1["requested_at_utc"],
            "2026-11-15T10:00:00Z"
        );
    }

    #[test]
    fn config_is_a_collection_with_the_preamble() {
        let src = tmp("cfg");
        windows_like(&src);
        let mut s = GuiState::default();
        s.set_source(SourceKind::Directory, &src.display().to_string());
        s.out_dir = src.join("out").display().to_string();
        let cfg = s.to_config().unwrap();
        assert!(cfg.inputs.is_empty());
        assert_eq!(cfg.frontend, "gui");
        let o = cfg.collect.as_ref().unwrap();
        assert_eq!(o.source, SourceSpec::Directory(src.clone()));
        assert!(!o.allow_same_volume);
        let names: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            names,
            [
                "ui_source_changed",
                "ui_output_folder_changed",
                "ui_start_clicked"
            ],
            "the output folder typed in the field is committed by Start"
        );
        let start = &cfg.preamble[2].1;
        assert_eq!(start["source"], "directory");
        assert_eq!(start["allow_same_volume"], false);
        assert!(
            cfg.command_line
                .iter()
                .any(|l| l == "groups=evtx,hives,prefetch,browsers,tasks")
        );
        s.set_source(
            SourceKind::Image,
            &src.join("missing.dd").display().to_string(),
        );
        assert!(
            s.to_config().is_err(),
            "a missing image is refused before the run"
        );
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn collection_events_drive_step_progress_and_results() {
        let mut s = GuiState::default();
        s.start();
        s.apply(&Event::Phase {
            phase: "preflight".into(),
            total: 0,
        });
        assert!(s.progress_text().contains(&s.tr("step_preflight")));
        s.apply(&Event::Phase {
            phase: "copy".into(),
            total: 4,
        });
        s.apply(&Event::Artifact {
            group: "hives".into(),
            source: "C:\\Windows\\System32\\config\\SYSTEM".into(),
            status: "collected".into(),
            code: "COLLECTED_RAW".into(),
        });
        s.apply(&Event::Progress {
            done: 1,
            total: 4,
            bytes_done: 2048,
            bytes_total: 0,
            elapsed_ms: 1000,
            eta_ms: Some(5000),
        });
        s.apply(&Event::Artifact {
            group: "evtx".into(),
            source: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx".into(),
            status: "not_collected".into(),
            code: "NOT_COLLECTED_NO_ADMIN".into(),
        });
        assert_eq!(s.progress.done, 2);
        assert!(
            (s.fraction() - 0.5).abs() < 1e-6,
            "by files while bytes_total is 0"
        );
        assert!(s.progress_text().starts_with("2 / 4") && s.progress_text().contains("2.0 KB"));
        assert!(
            s.timing_text(Some(1500)).ends_with("\u{2014}"),
            "no ETA while copying: {}",
            s.timing_text(None)
        );
        assert_eq!(
            s.step_text(),
            format!("{}: {} (2 / 4)", s.tr("step"), s.tr("step_copy"))
        );
        assert_eq!(s.counts(), (1, 1));
        s.set_not_collected_only(true);
        let rows = s.visible_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, "NOT_COLLECTED_NO_ADMIN");
        assert_eq!(
            s.finding_text("NOT_COLLECTED_NO_ADMIN"),
            "NOT_COLLECTED_NO_ADMIN \u{2014} Not collected: no administrator rights"
        );
        s.set_ui_lang("es");
        assert_ne!(
            s.finding_text("NOT_COLLECTED_NO_ADMIN"),
            "NOT_COLLECTED_NO_ADMIN"
        );
        assert_eq!(s.finding_text(""), "\u{2014}");
        s.apply(&Event::RunStarted {
            run_id: "R".into(),
            tool: "t".into(),
            version: "v".into(),
            frontend: "gui".into(),
            algorithms: vec![HashAlgo::Sha256],
            langs: vec!["en".into()],
            total_items: 2,
            total_bytes: 400,
        });
        assert_eq!(s.step.as_ref().unwrap().name, "verify");
        s.apply(&Event::Progress {
            done: 1,
            total: 2,
            bytes_done: 100,
            bytes_total: 400,
            elapsed_ms: 2000,
            eta_ms: Some(6000),
        });
        assert!((s.fraction() - 0.25).abs() < 1e-6);
        assert!(
            s.timing_text(Some(2500)).contains("6.0 s"),
            "ETA while verifying"
        );
        s.apply(&Event::RunFinished {
            items: 2,
            bytes: 400,
            errors: 0,
            elapsed_ms: 8000,
            high: 0,
            medium: 0,
            low: 1,
            info: 1,
            report_dir: "out/reports/R".into(),
            log_dir: "out/logs/R".into(),
            cancelled: false,
        });
        assert_eq!(s.phase, Phase::Finished);
        let o = s.outcome.as_ref().unwrap();
        assert_eq!(o.report, PathBuf::from("out/reports/R/statistics.en.html"));
        assert_eq!(o.package, PathBuf::from("out/reports/R/package"));
    }

    #[test]
    fn interface_language_and_trust_settings_are_audited() {
        let mut s = GuiState::default();
        s.set_ui_lang("fr");
        assert_eq!(s.tr("start"), "Lancer la collecte");
        s.set_ui_lang("es");
        assert_eq!(s.tr("start"), "Iniciar recolección");
        s.set_jurisdiction("fr");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("missing.p12");
        let src = tmp("trust");
        s.set_source(SourceKind::Directory, &src.display().to_string());
        s.set_out_dir(&src.join("out").display().to_string());
        assert!(s.to_config().is_err(), "missing certificate refused");
        s.set_sign_cert("");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.jurisdiction, "fr");
        assert!(cfg.tsa_url.is_none());
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            actions.contains(&"ui_interface_language_changed")
                && actions.contains(&"ui_timestamp_changed")
        );
        assert!(
            cfg.preamble
                .iter()
                .all(|(_, d)| !d.to_string().contains("password"))
        );
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn a_real_collection_from_gui_settings_is_audited() {
        let src = tmp("run");
        windows_like(&src);
        let out = tmp("run-out");
        let mut s = GuiState {
            timestamp: false, // tests stay offline
            ..Default::default()
        };
        s.set_source(SourceKind::Directory, &src.display().to_string());
        s.users = "alex.demo".into();
        s.set_out_dir(&out.display().to_string());
        let cfg = s.to_config().unwrap();
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_triage_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        let (collected, _) = s.counts();
        assert_eq!(collected, 5, "{:?}", s.artifacts);
        assert!(
            !s.artifacts.iter().any(|a| a.source.contains("sam.demo")),
            "users filter applied"
        );
        assert!(!s.artifacts.iter().any(|a| a.group == "volatile"));
        assert!(
            s.outcome
                .as_ref()
                .unwrap()
                .package
                .join("manifest.json")
                .is_file()
        );
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        assert!(
            log.contains("\"ui_source_changed\"")
                && log.contains("\"ui_output_folder_changed\"")
                && log.contains("\"ui_start_clicked\"")
                && log.contains("\"frontend\":\"gui\"")
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&out);
    }
}
