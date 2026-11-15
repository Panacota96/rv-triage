//! Renders the main window headless (no display, no GPU) to a PNG, for the documentation:
//!
//!     cargo run -p rv-triage-gui --example triage_screenshot -- docs/images/gui-main.png [en|es|fr]
//!
//! A synthetic folder laid out like a Windows volume (magic bytes only, made-up user names `alex.demo` and
//! `sam.demo`) is created in a temp folder and collected for real with two hash algorithms, the GUI state fed by
//! the core's events; then a few egui frames run and egui's tessellated meshes are rasterised on the CPU
//! (textured triangles, premultiplied alpha), so the picture is what the window draws, minus the GPU. On
//! Windows one event log is held open without sharing during the run, so the table also shows a
//! not-collected row (`NOT_COLLECTED_LOCKED`).
#![forbid(unsafe_code)]

use eframe::egui;
use egui::epaint::{ClippedPrimitive, Color32, ImageData, Primitive, TextureId};
use rv_triage_core::HashAlgo;
use rv_triage_gui::app::HashInvApp;
use rv_triage_gui::state::{GuiState, SourceKind};
use std::collections::HashMap;
use std::path::Path;

const W: usize = 1280;
const H: usize = 900;

/// Synthetic Windows-like volume root: every file starts with the magic bytes of its kind.
fn windows_like(root: &Path) {
    let files: [(&str, &[u8]); 12] = [
        (
            "Windows/System32/config/SYSTEM",
            b"regf\x01\0\0\0synthetic-system",
        ),
        (
            "Windows/System32/config/SOFTWARE",
            b"regf\x01\0\0\0synthetic-software",
        ),
        (
            "Windows/System32/config/SAM",
            b"regf\x01\0\0\0synthetic-sam",
        ),
        ("Windows/System32/config/SYSTEM.LOG1", b"DIRT synthetic log"),
        (
            "Windows/System32/winevt/Logs/Security.evtx",
            b"ElfFile\0synthetic",
        ),
        (
            "Windows/System32/winevt/Logs/System.evtx",
            b"ElfFile\0synthetic",
        ),
        ("Windows/Prefetch/CMD.EXE-0BD30981.pf", b"MAM\x04synthetic"),
        (
            "Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf",
            b"MAM\x04synthetic",
        ),
        (
            "Windows/System32/Tasks/DemoUpdater",
            b"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task/>",
        ),
        (
            "Users/alex.demo/NTUSER.DAT",
            b"regf\x01\0\0\0synthetic-alex",
        ),
        (
            "Users/alex.demo/AppData/Local/Microsoft/Edge/User Data/Default/History",
            b"SQLite format 3\0synthetic",
        ),
        ("Users/sam.demo/NTUSER.DAT", b"regf\x01\0\0\0synthetic-sam"),
    ];
    for (rel, body) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("folder");
        std::fs::write(p, body).expect("file");
    }
}

/// Windows: an exclusive handle (no sharing) makes the collector's open fail with a sharing violation.
#[cfg(windows)]
fn hold_locked(p: &Path) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(p)
        .ok()
}

#[cfg(not(windows))]
fn hold_locked(_: &Path) -> Option<std::fs::File> {
    None
}

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

impl Tex {
    /// Bilinear sample of premultiplied texels, clamped at the edges.
    fn sample(&self, u: f32, v: f32) -> [f32; 4] {
        let x = (u * self.w as f32 - 0.5).clamp(0.0, (self.w - 1) as f32);
        let y = (v * self.h as f32 - 0.5).clamp(0.0, (self.h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(self.w - 1), (y0 + 1).min(self.h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = self.px[y * self.w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut o = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bot = c[i] + (d[i] - c[i]) * fx;
            o[i] = (top + (bot - top) * fy) / 255.0;
        }
        o
    }
}

fn rasterise(
    prims: &[ClippedPrimitive],
    textures: &HashMap<TextureId, Tex>,
    ppp: f32,
) -> Vec<[f32; 4]> {
    let mut canvas = vec![[0.0f32, 0.0, 0.0, 1.0]; W * H];
    for p in prims {
        let Primitive::Mesh(mesh) = &p.primitive else {
            continue;
        };
        let Some(tex) = textures.get(&mesh.texture_id) else {
            continue;
        };
        let cx0 = (p.clip_rect.min.x * ppp).max(0.0).floor() as i64;
        let cy0 = (p.clip_rect.min.y * ppp).max(0.0).floor() as i64;
        let cx1 = ((p.clip_rect.max.x * ppp).ceil() as i64).min(W as i64);
        let cy1 = ((p.clip_rect.max.y * ppp).ceil() as i64).min(H as i64);
        for t in mesh.indices.chunks_exact(3) {
            let v = [
                &mesh.vertices[t[0] as usize],
                &mesh.vertices[t[1] as usize],
                &mesh.vertices[t[2] as usize],
            ];
            let pt: Vec<[f32; 2]> = v.iter().map(|v| [v.pos.x * ppp, v.pos.y * ppp]).collect();
            let area = (pt[1][0] - pt[0][0]) * (pt[2][1] - pt[0][1])
                - (pt[2][0] - pt[0][0]) * (pt[1][1] - pt[0][1]);
            if area.abs() < 1e-9 {
                continue;
            }
            let minx = pt.iter().map(|p| p[0]).fold(f32::MAX, f32::min).floor() as i64;
            let maxx = pt.iter().map(|p| p[0]).fold(f32::MIN, f32::max).ceil() as i64;
            let miny = pt.iter().map(|p| p[1]).fold(f32::MAX, f32::min).floor() as i64;
            let maxy = pt.iter().map(|p| p[1]).fold(f32::MIN, f32::max).ceil() as i64;
            for y in miny.max(cy0)..maxy.min(cy1) {
                for x in minx.max(cx0)..maxx.min(cx1) {
                    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                    let e = |a: [f32; 2], b: [f32; 2]| {
                        (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
                    };
                    let w0 = e(pt[1], pt[2]) / area;
                    let w1 = e(pt[2], pt[0]) / area;
                    let w2 = e(pt[0], pt[1]) / area;
                    if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                        continue;
                    }
                    let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                    let vv = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                    let s = tex.sample(u, vv);
                    let col = |i: usize| {
                        let c = |v: &egui::epaint::Vertex| v.color.to_array()[i] as f32 / 255.0;
                        w0 * c(v[0]) + w1 * c(v[1]) + w2 * c(v[2])
                    };
                    let src = [s[0] * col(0), s[1] * col(1), s[2] * col(2), s[3] * col(3)];
                    let d = &mut canvas[y as usize * W + x as usize];
                    for i in 0..4 {
                        d[i] = src[i] + d[i] * (1.0 - src[3]);
                    }
                }
            }
        }
    }
    canvas
}

fn main() {
    let mut args = std::env::args().skip(1);
    let target = std::path::PathBuf::from(args.next().unwrap_or_else(|| "gui-main.png".into()));
    let ui_lang = args.next().unwrap_or_else(|| "en".into());
    let tmp = std::env::temp_dir().join(format!("rv-triage-screenshot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let volume = tmp.join("DEMO-VOLUME");
    windows_like(&volume);
    let out = tmp.join("rv-out");

    // The settings an examiner would choose (each one audited like a click).
    let mut s = GuiState::default();
    s.set_timestamp(false, &s.tsa_url.clone()); // offline
    s.actor = "Examiner Demo".into();
    s.set_source(SourceKind::Directory, &volume.display().to_string());
    s.toggle_algo(HashAlgo::Blake3).expect("second algorithm");
    s.set_out_dir(&out.display().to_string());
    s.case_id = "CASE-DEMO-001".into();
    s.set_ui_lang(&ui_lang);
    let cfg = s.to_config().expect("valid settings");
    s.start();
    let lock = hold_locked(&volume.join("Windows/System32/winevt/Logs/System.evtx"));
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let summary = rv_triage_core::run(&cfg, &mut |e| s.apply(e), &cancel).expect("collection");
    drop(lock);
    // Paths shown as the examiner would see them on the collection machine.
    let prefix = volume.display().to_string();
    for a in &mut s.artifacts {
        if let Some(rest) = a.source.strip_prefix(&prefix) {
            a.source = format!("D:\\DEMO-VOLUME{}", rest);
        }
    }
    s.out_dir = r"E:\rv-out".into();
    s.source_path = r"D:\DEMO-VOLUME".into();
    let mut app = HashInvApp::from_state(s);

    let ctx = egui::Context::default();
    let mut textures: HashMap<TextureId, Tex> = HashMap::new();
    let mut last = None;
    for frame in 0..4 {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(W as f32, H as f32),
            )),
            time: Some(frame as f64 * 0.1),
            focused: true,
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw, |ui| app.draw(ui));
        for (id, deltas) in &output.textures_delta.set {
            for d in deltas {
                let ImageData::Color(img) = &d.image;
                match d.pos {
                    None => {
                        textures.insert(
                            *id,
                            Tex {
                                w: img.size[0],
                                h: img.size[1],
                                px: img.pixels.clone(),
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = textures.get_mut(id).expect("patch of a known texture");
                        for y in 0..img.size[1] {
                            for x in 0..img.size[0] {
                                t.px[(y0 + y) * t.w + x0 + x] = img.pixels[y * img.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
        // Applied above (this renderer keeps every texture until the end).
        output.textures_delta.clear();
        last = Some(output);
    }
    let output = last.expect("frames ran");
    let ppp = output.pixels_per_point;
    let prims = ctx.tessellate(output.shapes, ppp);
    let canvas = rasterise(&prims, &textures, ppp);
    let rgba: Vec<u8> = canvas
        .iter()
        .flat_map(|p| {
            let a = p[3].clamp(1e-6, 1.0);
            [p[0] / a, p[1] / a, p[2] / a, 1.0].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as u8)
        })
        .collect();
    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).expect("output folder");
    }
    let file = std::fs::File::create(&target).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), W as u32, H as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .expect("png")
        .write_image_data(&rgba)
        .expect("png data");
    let (c, n) = app.state().counts();
    println!(
        "wrote {} ({W}x{H}, {} meshes; {} collected, {} not collected; run {})",
        target.display(),
        prims.len(),
        c,
        n,
        summary.run_id
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
