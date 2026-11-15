//! The window. Drawing only: rules live in `state.rs`, work lives in the core (on a worker thread).
//! Rakvor dark theme; interface language EN/ES/FR switchable at any time (texts from i18n "ui").
//!
//! Layout: header + elevation banner on top, the collection settings on the left (source, groups, users,
//! hashes, package/reports, trust, Start), the progress and the results table in the centre.

use crate::state::{GuiState, Phase, SourceKind};
use eframe::egui;
use rv_triage_core::collect::Group;
use rv_triage_core::{Event, HashAlgo, RunConfig, RunSummary, TOOL_VERSION};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

// Rakvor palette
const NIGHT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x11, 0x17);
const NIGHT2: egui::Color32 = egui::Color32::from_rgb(0x1A, 0x1F, 0x26);
const BLUE: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x5C, 0xFF);
const VIOLET: egui::Color32 = egui::Color32::from_rgb(0x6B, 0x00, 0xFF);
const CYAN: egui::Color32 = egui::Color32::from_rgb(0x00, 0xE5, 0xFF);
const MIST: egui::Color32 = egui::Color32::from_rgb(0xE6, 0xE6, 0xE6);
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xB0, 0x40);
const GREEN: egui::Color32 = egui::Color32::from_rgb(0x5C, 0xD6, 0x8A);
const RED: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x6B, 0x6B);
const UI_LANGS: [(&str, &str); 3] = [("en", "English"), ("es", "Español"), ("fr", "Français")];

enum Msg {
    Event(Event),
    Done(Result<RunSummary, String>),
}

pub struct HashInvApp {
    state: GuiState,
    rx: Option<Receiver<Msg>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    notice: Option<String>,
    themed: bool,
}

/// Applies the Rakvor dark theme.
pub fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = NIGHT;
    v.window_fill = NIGHT2;
    v.extreme_bg_color = NIGHT2; // text fields
    v.widgets.inactive.bg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2B, 0x32, 0x40));
    v.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2B, 0x32, 0x40));
    v.faint_bg_color = NIGHT2;
    v.override_text_color = Some(MIST);
    v.selection.bg_fill = BLUE;
    v.hyperlink_color = CYAN;
    v.widgets.inactive.bg_fill = NIGHT2;
    v.widgets.inactive.weak_bg_fill = NIGHT2;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, CYAN);
    v.widgets.active.bg_fill = BLUE;
    ctx.set_visuals(v);
}

/// A left-aligned, truncated table cell of a fixed width.
fn cell(ui: &mut egui::Ui, width: f32, height: f32, text: impl Into<egui::WidgetText>) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_width(width);
            ui.add(egui::Label::new(text).truncate());
        },
    );
}

impl HashInvApp {
    pub fn new() -> Self {
        Self::from_state(GuiState::default())
    }

    /// A window on prepared settings (tests, the screenshot example).
    pub fn from_state(state: GuiState) -> Self {
        HashInvApp {
            state,
            rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            notice: None,
            themed: false,
        }
    }

    pub fn state(&self) -> &GuiState {
        &self.state
    }

    /// Starts from the executable's arguments: a folder or image file given to the exe becomes the source;
    /// `--elevation-requested-at` (from "Restart as administrator") is recorded; `--case-dir` is ignored with a
    /// note (a collection writes a package, registered afterwards with rv-hashinv).
    pub fn from_launch(args: crate::launch::LaunchArgs) -> Self {
        let mut app = Self::new();
        if let Some(at) = &args.elevation_requested_at {
            app.state.restarted_after_request(at);
        }
        let mut notes = args.notes.clone();
        if let Some(first) = args.inputs.first() {
            app.state.set_source_from_path(first);
        }
        for extra in args.inputs.iter().skip(1) {
            notes.push(format!(
                "one source per collection: {} ignored",
                extra.display()
            ));
        }
        if let Some(dir) = &args.case_dir {
            notes.push(format!(
                "{} {} ignored: a collection writes a package; register it with rv-hashinv",
                crate::launch::CASE_DIR_FLAG,
                dir.display()
            ));
        }
        for n in &notes {
            app.state.note_launch_problem(n);
        }
        if !notes.is_empty() {
            app.notice = Some(notes.join("\n"));
        }
        app
    }

    fn start(&mut self, ctx: &egui::Context) {
        let cfg: RunConfig = match self.state.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.notice = Some(e);
                return;
            }
        };
        self.notice = None;
        self.state.start();
        self.cancel.store(false, Ordering::SeqCst);
        self.started = Some(Instant::now());
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let cancel = self.cancel.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let r2 = repaint.clone();
            let mut sink = move |e: &Event| {
                let _ = tx2.send(Msg::Event(e.clone()));
                r2.request_repaint();
            };
            let result = rv_triage_core::run(&cfg, &mut sink, &cancel);
            let _ = tx.send(Msg::Done(result));
            repaint.request_repaint();
        });
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut finished = false;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => {
                    if let Event::Timestamp { status, reason, .. } = &e
                        && status != "ok"
                    {
                        self.state
                            .warnings
                            .push(format!("timestamp: {}", reason.as_deref().unwrap_or("-")));
                    }
                    self.state.apply(&e)
                }
                Msg::Done(Ok(_)) => finished = true,
                Msg::Done(Err(e)) => {
                    self.state.fail(e);
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.started = None;
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(38.0, 38.0), egui::Sense::hover());
            ui.painter().rect(
                rect,
                8.0,
                NIGHT2,
                egui::Stroke::new(2.0, BLUE),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 3.0),
                egui::Align2::CENTER_CENTER,
                "RV",
                egui::FontId::proportional(16.0),
                MIST,
            );
            ui.painter().line_segment(
                [
                    rect.center() + egui::vec2(-8.0, 10.0),
                    rect.center() + egui::vec2(8.0, 10.0),
                ],
                egui::Stroke::new(2.0, CYAN),
            );
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("R A K V O R  \u{00B7}  RV Triage")
                        .strong()
                        .size(16.0),
                );
                let desc = rv_triage_core::i18n::catalog(&self.state.ui_lang).brand()["descriptor"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                ui.label(egui::RichText::new(desc).color(CYAN).size(10.0));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let current = UI_LANGS
                    .iter()
                    .find(|(k, _)| *k == self.state.ui_lang)
                    .map(|(_, v)| *v)
                    .unwrap_or("English");
                let mut chosen = None;
                egui::ComboBox::from_id_salt("ui-lang")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (k, v) in UI_LANGS {
                            if ui.selectable_label(self.state.ui_lang == k, v).clicked() {
                                chosen = Some(k);
                            }
                        }
                    });
                if let Some(k) = chosen {
                    self.state.set_ui_lang(k);
                }
                ui.label(self.state.tr("ui_lang"));
                ui.weak(format!("v{}", TOOL_VERSION));
            });
        });
        ui.weak(self.state.tr("audit_note"));
        let (r, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 3.0), egui::Sense::hover());
        let third = r.width() / 3.0;
        for (i, c) in [BLUE, VIOLET, CYAN].iter().enumerate() {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    r.min + egui::vec2(third * i as f32, 0.0),
                    egui::vec2(third, 3.0),
                ),
                0.0,
                *c,
            );
        }
        ui.add_space(4.0);
        self.elevation_banner(ui);
    }

    /// Elevated: what that gives. Not elevated: what will be missing, and the relaunch button.
    fn elevation_banner(&mut self, ui: &mut egui::Ui) {
        let (fill, text) = if self.state.elevated {
            (
                egui::Color32::from_rgb(0x10, 0x2A, 0x1C),
                self.state.tr("elevated_ok"),
            )
        } else {
            (
                egui::Color32::from_rgb(0x33, 0x26, 0x0E),
                self.state.tr("elevated_no"),
            )
        };
        egui::Frame::new()
            .fill(fill)
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    if self.state.elevated {
                        ui.label(egui::RichText::new(text).color(GREEN).strong());
                        return;
                    }
                    let label = self.state.tr("restart_admin");
                    let tip = self.state.tr("restart_admin_tip");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let b = ui
                            .add_enabled(!self.state.is_running(), egui::Button::new(label))
                            .on_hover_text(tip);
                        if b.clicked() {
                            let at = self.state.request_elevation();
                            match crate::launch::relaunch_elevated(&at) {
                                Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                                Err(e) => {
                                    self.state.elevation_failed(&e);
                                    self.notice =
                                        Some(format!("{}: {}", self.state.tr("restart_failed"), e));
                                }
                            }
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(egui::RichText::new(text).color(AMBER).strong())
                                    .wrap(),
                            );
                        });
                    });
                });
            });
    }

    fn section_title(ui: &mut egui::Ui, text: String) {
        ui.add_space(6.0);
        ui.label(egui::RichText::new(text).color(CYAN).strong().size(15.0));
    }

    #[cfg(windows)]
    fn pick_source(&mut self, k: SourceKind) {
        let picked = match k {
            SourceKind::Live => None,
            SourceKind::Image => rfd::FileDialog::new()
                .add_filter("Volume image", &["dd", "img", "raw", "001", "bin"])
                .add_filter("*", &["*"])
                .pick_file(),
            SourceKind::Directory => rfd::FileDialog::new().pick_folder(),
        };
        if let Some(p) = picked {
            self.state.set_source(k, &p.display().to_string());
        }
    }

    fn source_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("source"));
        ui.add(egui::Label::new(egui::RichText::new(self.state.tr("source_help")).weak()).wrap());
        ui.add_enabled_ui(enabled, |ui| {
            for (k, key) in [
                (SourceKind::Live, "source_live"),
                (SourceKind::Image, "source_image"),
                (SourceKind::Directory, "source_folder"),
            ] {
                let r = ui.radio(self.state.source_kind == k, self.state.tr(key));
                if r.clicked() && self.state.source_kind != k {
                    self.state.set_source_kind(k);
                    #[cfg(windows)]
                    self.pick_source(k);
                }
            }
            if self.state.source_kind != SourceKind::Live {
                ui.horizontal(|ui| {
                    let hint = self.state.tr("source_path_hint");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.state.source_path)
                            .hint_text(hint)
                            .desired_width(300.0),
                    );
                    if r.lost_focus() {
                        self.state.commit_entries();
                    }
                    #[cfg(windows)]
                    if ui.button(self.state.tr("choose")).clicked() {
                        let k = self.state.source_kind;
                        self.pick_source(k);
                    }
                });
            }
            // A folder or image dropped on the window becomes the source.
            let dropped: Option<PathBuf> = ui.ctx().input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .find(|p| !p.as_os_str().is_empty())
            });
            if let Some(p) = dropped {
                self.state.set_source_from_path(&p);
            }
        });
    }

    fn groups_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("groups"));
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("groups-grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    for (i, g) in Group::ALL.into_iter().enumerate() {
                        let mut on = self.state.groups.contains(&g);
                        let can = self.state.can_toggle_group(g);
                        let mut r = ui.add_enabled(
                            can,
                            egui::Checkbox::new(&mut on, self.state.group_label(g.name())),
                        );
                        if g == Group::Volatile {
                            r = r
                                .on_hover_text(self.state.tr("volatile_help"))
                                .on_disabled_hover_text(self.state.tr("volatile_only_live"));
                        }
                        if r.changed() {
                            self.state.toggle_group(g);
                        }
                        if i % 2 == 1 {
                            ui.end_row();
                        }
                    }
                });
            if !self.state.volatile_available() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(self.state.tr("volatile_only_live")).weak(),
                    )
                    .wrap(),
                );
            }
            ui.horizontal(|ui| {
                ui.label(self.state.tr("users"));
                let hint = self.state.tr("users_hint");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.state.users)
                        .hint_text(hint)
                        .desired_width(ui.available_width()),
                );
                if r.lost_focus() {
                    self.state.commit_entries();
                }
            });
        });
    }

    fn hashing_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("hashes"));
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal_wrapped(|ui| {
                for a in HashAlgo::ALL {
                    let mut on = self.state.selected.contains(&a);
                    let tip = if self.state.can_toggle(a) {
                        String::new()
                    } else if on {
                        self.state.tr("hash_tip_one")
                    } else {
                        self.state.tr("hash_tip_two")
                    };
                    let r = ui.add_enabled(
                        self.state.can_toggle(a),
                        egui::Checkbox::new(&mut on, a.name()),
                    );
                    let r = if tip.is_empty() {
                        r
                    } else {
                        r.on_disabled_hover_text(tip)
                    };
                    if r.changed()
                        && let Err(e) = self.state.toggle_algo(a)
                    {
                        self.notice = Some(e);
                    }
                }
            });
        });
    }

    fn report_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("reports"));
        let tr = |k: &str| self.state.tr(k);
        let (l_lang, l_out, l_browse, l_exam, l_case, l_hint, l_all, l_out_hint) = (
            tr("report_lang"),
            tr("out_dir"),
            tr("browse"),
            tr("examiner"),
            tr("case"),
            tr("case_hint"),
            tr("lang_all"),
            tr("out_hint"),
        );
        let (l_same, l_same_warn) = (tr("allow_same_volume"), tr("allow_same_volume_warn"));
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("report-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_out);
                    ui.horizontal(|ui| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut self.state.out_dir)
                                .hint_text(l_out_hint)
                                .desired_width(250.0),
                        );
                        if r.lost_focus() {
                            self.state.commit_entries();
                        }
                        #[cfg(windows)]
                        if ui.button(&l_browse).clicked()
                            && let Some(d) = rfd::FileDialog::new().pick_folder()
                        {
                            self.state.set_out_dir(&d.display().to_string());
                        }
                        let _ = &l_browse;
                    });
                    ui.end_row();
                    ui.label("");
                    let mut same = self.state.allow_same_volume;
                    if ui.checkbox(&mut same, l_same).changed() {
                        self.state.set_allow_same_volume(same);
                    }
                    ui.end_row();
                    ui.label(l_lang);
                    let choices = [
                        ("en", "English".to_string()),
                        ("es", "Español".to_string()),
                        ("fr", "Français".to_string()),
                        ("all", l_all),
                    ];
                    let current = choices
                        .iter()
                        .find(|(k, _)| *k == self.state.lang)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for (k, v) in &choices {
                                if ui.selectable_label(self.state.lang == *k, v).clicked() {
                                    chosen = Some(*k);
                                }
                            }
                        });
                    if let Some(k) = chosen {
                        self.state.set_lang(k);
                    }
                    ui.end_row();
                    ui.label(l_exam);
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.state.actor).desired_width(250.0),
                    );
                    if r.lost_focus() {
                        self.state.commit_entries();
                    }
                    ui.end_row();
                    ui.label(l_case);
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.state.case_id)
                            .hint_text(l_hint)
                            .desired_width(250.0),
                    );
                    if r.lost_focus() {
                        self.state.commit_entries();
                    }
                    ui.end_row();
                });
            if self.state.allow_same_volume {
                ui.add(egui::Label::new(egui::RichText::new(l_same_warn).color(AMBER)).wrap());
            }
        });
    }

    fn trust_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("trust"));
        let tr = |k: &str| self.state.tr(k);
        let (l_jur, l_co, l_fr, l_tsa, l_cert, l_pass, l_browse) = (
            tr("jurisdiction"),
            tr("jur_co"),
            tr("jur_fr"),
            tr("tsa"),
            tr("sign_cert"),
            tr("sign_pass"),
            tr("browse"),
        );
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("trust-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_jur);
                    let current = if self.state.jurisdiction == "fr" {
                        l_fr.clone()
                    } else {
                        l_co.clone()
                    };
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("jur")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_label(self.state.jurisdiction == "co", &l_co)
                                .clicked()
                            {
                                chosen = Some("co");
                            }
                            if ui
                                .selectable_label(self.state.jurisdiction == "fr", &l_fr)
                                .clicked()
                            {
                                chosen = Some("fr");
                            }
                        });
                    if let Some(j) = chosen {
                        self.state.set_jurisdiction(j);
                    }
                    ui.end_row();
                    ui.label(l_tsa);
                    ui.horizontal(|ui| {
                        let mut on = self.state.timestamp;
                        let mut url = self.state.tsa_url.clone();
                        let c = ui.checkbox(&mut on, "");
                        let t = ui.add_enabled(
                            on,
                            egui::TextEdit::singleline(&mut url).desired_width(230.0),
                        );
                        if c.changed() || t.lost_focus() {
                            self.state.set_timestamp(on, &url);
                        } else {
                            self.state.tsa_url = url;
                        }
                    });
                    ui.end_row();
                    ui.label(l_cert);
                    ui.horizontal(|ui| {
                        let mut path = self.state.sign_cert.clone();
                        let r = ui.add(egui::TextEdit::singleline(&mut path).desired_width(160.0));
                        if r.lost_focus() || r.changed() {
                            self.state.set_sign_cert(&path);
                        }
                        #[cfg(windows)]
                        if ui.button(&l_browse).clicked()
                            && let Some(f) = rfd::FileDialog::new()
                                .add_filter("PKCS#12", &["p12", "pfx"])
                                .pick_file()
                        {
                            self.state.set_sign_cert(&f.display().to_string());
                        }
                        let _ = &l_browse;
                    });
                    ui.end_row();
                    ui.label(l_pass);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.state.sign_password)
                            .password(true)
                            .desired_width(230.0),
                    );
                    ui.end_row();
                });
        });
    }

    fn start_row(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if self.state.is_running() {
                if ui.button(self.state.tr("cancel")).clicked() {
                    self.cancel.store(true, Ordering::SeqCst);
                    self.notice = Some(self.state.tr("cancelling"));
                }
            } else {
                let start = egui::Button::new(
                    egui::RichText::new(self.state.tr("start"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(BLUE);
                let r = ui.add_enabled(self.state.can_start(), start);
                let r = match self.state.start_blocker() {
                    Some(why) => r.on_disabled_hover_text(why),
                    None => r,
                };
                if r.clicked() {
                    let ctx = ui.ctx().clone();
                    self.start(&ctx);
                }
                if let Some(why) = self.state.start_blocker() {
                    ui.weak(why);
                }
            }
        });
        if let Some(n) = &self.notice {
            ui.add(egui::Label::new(egui::RichText::new(n).color(AMBER)).wrap());
        }
        ui.add_space(6.0);
    }

    fn progress_section(&mut self, ui: &mut egui::Ui) {
        ui.add(
            egui::ProgressBar::new(self.state.fraction())
                .text(self.state.progress_text())
                .fill(BLUE)
                .animate(self.state.is_running()),
        );
        let step = self.state.step_text();
        if !step.is_empty() && self.state.is_running() {
            ui.label(egui::RichText::new(step).color(CYAN));
        }
        let live = self.started.map(|s| s.elapsed().as_millis() as u64);
        ui.label(self.state.timing_text(live));
        if !self.state.current_item.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!(
                        "{}: {}",
                        self.state.tr("now"),
                        self.state.current_item
                    ))
                    .weak(),
                )
                .truncate(),
            );
        }
        match &self.state.phase {
            Phase::Failed(e) => {
                ui.colored_label(RED, format!("{}: {}", self.state.tr("failed"), e));
            }
            Phase::Finished | Phase::Cancelled => {
                if let Some(o) = self.state.outcome.clone() {
                    ui.separator();
                    let title = if self.state.phase == Phase::Cancelled {
                        self.state.tr("cancelled")
                    } else {
                        self.state.tr("done")
                    };
                    let (c, n) = self.state.counts();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(title).color(CYAN).strong());
                        ui.label(format!(
                            "{} {} \u{00B7} {} {} \u{00B7} {} {} \u{00B7} {} {} \u{00B7} {}: {} / {} / {} / {}",
                            c,
                            self.state.tr("collected_count"),
                            n,
                            self.state.tr("not_collected_count"),
                            o.items,
                            self.state.tr("files"),
                            o.errors,
                            self.state.tr("errors"),
                            self.state.tr("findings"),
                            o.high,
                            o.medium,
                            o.low,
                            o.info
                        ));
                    });
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(self.state.tr("open_package")).clicked() {
                            open_path(&o.package);
                        }
                        if ui.button(self.state.tr("open_report")).clicked() {
                            open_path(&o.report);
                        }
                        if ui.button(self.state.tr("open_logs")).clicked() {
                            open_path(&o.log_dir);
                        }
                    });
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(self.state.tr("register_hint")).color(CYAN),
                        )
                        .wrap(),
                    );
                }
            }
            _ => {}
        }
        if !self.state.warnings.is_empty() {
            egui::CollapsingHeader::new(format!(
                "{} ({})",
                self.state.tr("warnings"),
                self.state.warnings.len()
            ))
            .show(ui, |ui| {
                for w in &self.state.warnings {
                    ui.label(w);
                }
            });
        }
    }

    fn results_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        let (c, n) = self.state.counts();
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(self.state.tr("results"))
                    .color(CYAN)
                    .strong()
                    .size(15.0),
            );
            ui.weak(format!(
                "{} {} \u{00B7} {} {}",
                c,
                self.state.tr("collected_count"),
                n,
                self.state.tr("not_collected_count")
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut only = self.state.not_collected_only;
                if ui
                    .checkbox(&mut only, self.state.tr("not_collected_only"))
                    .changed()
                {
                    self.state.set_not_collected_only(only);
                }
            });
        });
        ui.weak(self.state.tr("results_note"));
        let row_h = 20.0;
        let total = ui.available_width();
        let (w_group, w_status, w_finding) = (120.0, 100.0, 250.0);
        let spacing = ui.spacing().item_spacing.x * 3.0;
        let w_source = (total - w_group - w_status - w_finding - spacing - 12.0).max(120.0);
        ui.horizontal(|ui| {
            for (w, key) in [
                (w_group, "col_group"),
                (w_source, "col_source"),
                (w_status, "col_status"),
                (w_finding, "col_finding"),
            ] {
                cell(
                    ui,
                    w,
                    row_h,
                    egui::RichText::new(self.state.tr(key)).strong(),
                );
            }
        });
        ui.separator();
        let rows: Vec<_> = self.state.visible_rows().into_iter().cloned().collect();
        if rows.is_empty() {
            ui.weak(self.state.tr("no_results"));
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("results")
            .auto_shrink([false, false])
            .show_rows(ui, row_h, rows.len(), |ui, range| {
                for r in &rows[range] {
                    ui.horizontal(|ui| {
                        cell(ui, w_group, row_h, self.state.group_label(&r.group));
                        cell(
                            ui,
                            w_source,
                            row_h,
                            egui::RichText::new(&r.source).size(12.5),
                        );
                        let color = if r.collected() { GREEN } else { AMBER };
                        cell(
                            ui,
                            w_status,
                            row_h,
                            egui::RichText::new(self.state.status_label(&r.status)).color(color),
                        );
                        cell(ui, w_finding, row_h, self.state.finding_text(&r.code));
                    })
                    .response
                    .on_hover_text(&r.source);
                }
            });
    }

    /// Draws one frame (also used by the headless screenshot example).
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        if !self.themed {
            apply_theme(ui.ctx());
            self.themed = true;
        }
        self.drain();
        if self.state.is_running() {
            // Keep the elapsed timer moving even when no event arrives (large files).
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        let enabled = !self.state.is_running();
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(4.0);
            self.header(ui);
            ui.add_space(4.0);
        });
        egui::Panel::left("settings")
            .resizable(true)
            .default_size(500.0)
            .size_range(380.0..=700.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("settings-scroll")
                    .show(ui, |ui| {
                        self.source_section(ui, enabled);
                        self.groups_section(ui, enabled);
                        self.hashing_section(ui, enabled);
                        self.report_section(ui, enabled);
                        self.trust_section(ui, enabled);
                        self.start_row(ui);
                    });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.0);
            self.progress_section(ui);
            self.results_section(ui);
        });
    }
}

impl Default for HashInvApp {
    fn default() -> Self {
        Self::new()
    }
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

impl eframe::App for HashInvApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::parse_launch_args;

    fn launch(args: &[&str]) -> HashInvApp {
        HashInvApp::from_launch(parse_launch_args(args.iter().map(std::ffi::OsString::from)))
    }

    fn actions(app: &HashInvApp) -> Vec<&str> {
        app.state
            .ui_actions
            .iter()
            .map(|(a, _)| a.as_str())
            .collect()
    }

    #[test]
    fn a_path_given_to_the_exe_becomes_the_source() {
        let app = launch(&["disk.dd"]);
        assert_eq!(app.state.source_kind, SourceKind::Image);
        assert_eq!(app.state.source_path, "disk.dd");
        assert_eq!(actions(&app), ["ui_source_changed"]);
        assert!(app.notice.is_none());
        let dir = std::env::temp_dir();
        let app = launch(&[dir.to_str().unwrap(), "extra.dd"]);
        assert_eq!(app.state.source_kind, SourceKind::Directory);
        assert_eq!(
            actions(&app),
            ["ui_source_changed", "ui_launch_argument_ignored"]
        );
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("extra.dd"))
        );
    }

    #[test]
    fn launch_without_arguments_is_the_live_system() {
        let app = launch(&[]);
        assert_eq!(app.state.source_kind, SourceKind::Live);
        assert!(actions(&app).is_empty());
    }

    #[test]
    fn case_dir_from_the_launcher_is_noted_and_ignored() {
        for args in [&["--case-dir", "X"][..], &["--case-dir"][..]] {
            let app = launch(args);
            assert_eq!(actions(&app), ["ui_launch_argument_ignored"], "{:?}", args);
            let d = &app.state.ui_actions[0].1;
            assert!(d["at_utc"].as_str().is_some_and(|t| t.ends_with('Z')));
            assert!(
                app.notice
                    .as_deref()
                    .is_some_and(|n| n.contains("--case-dir"))
            );
        }
    }

    #[test]
    fn elevated_relaunch_is_recorded_in_the_new_window() {
        let app = launch(&["--elevation-requested-at=2026-11-15T10:00:00Z"]);
        assert_eq!(actions(&app), ["ui_restarted_as_admin"]);
        let d = &app.state.ui_actions[0].1;
        assert_eq!(d["requested_at_utc"], "2026-11-15T10:00:00Z");
        assert_eq!(d["elevated"], app.state.elevated);
    }
}
