//! What each group collects, resolved against a source. Missing files are simply absent (a Windows 10 machine
//! without Firefox has no Firefox history); a folder that exists but cannot be listed is reported as `Unlisted`,
//! so the reports say which files were not collected and why.
//!
//! | group | volume paths |
//! | --- | --- |
//! | hives | `Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}` + `.LOG1`/`.LOG2`; per user `NTUSER.DAT` and `AppData/Local/Microsoft/Windows/UsrClass.dat` + their `.LOG1`/`.LOG2` |
//! | evtx | `Windows/System32/winevt/Logs/*.evtx` |
//! | prefetch | `Windows/Prefetch/*.pf` |
//! | browsers | per user: Edge and Chrome `User Data/<profile>/History` (+`-journal`, `-wal`); Firefox `Profiles/<profile>/places.sqlite` (+`-wal`, `-journal`) |
//! | tasks | every file under `Windows/System32/Tasks` |

use super::{Group, Resolved, Source, Target};
use std::io;

/// Profile folders that are links to other folders, not user profiles.
const NOT_PROFILES: &[&str] = &["All Users", "Default User"];
const SYSTEM_HIVES: &[&str] = &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
const MAX_DEPTH: usize = 16;

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", dir, name)
    }
}

struct Walker<'a> {
    src: &'a dyn Source,
    out: Vec<Resolved>,
}

impl Walker<'_> {
    /// Lists `dir`; `None` when it does not exist, records `Unlisted` when it exists but cannot be read.
    fn list(&mut self, group: Group, dir: &str) -> Option<Vec<super::DirEntry>> {
        match self.src.list(dir) {
            Ok(v) => Some(v),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                self.out.push(Resolved::Unlisted {
                    group,
                    path: dir.to_string(),
                    error: e.kind(),
                    message: e.to_string(),
                    raw_os_error: e.raw_os_error(),
                });
                None
            }
        }
    }

    /// The child of `dir` named `name` (case-insensitive), as stored.
    fn child(&mut self, group: Group, dir: &str, name: &str, want_dir: bool) -> Option<String> {
        self.list(group, dir)?
            .into_iter()
            .find(|e| e.is_dir == want_dir && e.name.eq_ignore_ascii_case(name))
            .map(|e| join(dir, &e.name))
    }

    /// Follows `a/b/c` case-insensitively from the root (every part a folder).
    fn folder(&mut self, group: Group, path: &str) -> Option<String> {
        let mut cur = String::new();
        for part in path.split('/') {
            cur = self.child(group, &cur, part, true)?;
        }
        Some(cur)
    }

    fn file(&mut self, group: Group, path: String) {
        self.out.push(Resolved::File(Target { group, path }));
    }

    /// Files in `dir` whose name ends with `suffix` (case-insensitive); `""` = every file.
    fn files_with(&mut self, group: Group, dir: &str, suffix: &str) {
        let Some(entries) = self.list(group, dir) else {
            return;
        };
        for e in entries {
            if !e.is_dir && e.name.to_ascii_lowercase().ends_with(suffix) {
                self.file(group, join(dir, &e.name));
            }
        }
    }

    /// `base` and its `.LOG1` / `.LOG2` transaction logs, when present in `dir`.
    fn with_logs(&mut self, group: Group, dir: &str, entries: &[super::DirEntry], base: &str) {
        for want in [
            base.to_string(),
            format!("{}.LOG1", base),
            format!("{}.LOG2", base),
        ] {
            if let Some(e) = entries
                .iter()
                .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(&want))
            {
                self.file(group, join(dir, &e.name));
            }
        }
    }

    /// SQLite database `name` and its `-journal` / `-wal` siblings.
    fn sqlite(&mut self, group: Group, dir: &str, entries: &[super::DirEntry], name: &str) {
        for want in [
            name.to_string(),
            format!("{}-journal", name),
            format!("{}-wal", name),
        ] {
            if let Some(e) = entries
                .iter()
                .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(&want))
            {
                self.file(group, join(dir, &e.name));
            }
        }
    }

    fn tree(&mut self, group: Group, dir: &str, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(entries) = self.list(group, dir) else {
            return;
        };
        for e in entries {
            let p = join(dir, &e.name);
            if e.is_dir {
                self.tree(group, &p, depth + 1);
            } else {
                self.file(group, p);
            }
        }
    }

    fn profiles(&mut self, group: Group, users: &[String]) -> Vec<String> {
        let Some(users_dir) = self.folder(group, "Users") else {
            return vec![];
        };
        let Some(entries) = self.list(group, &users_dir) else {
            return vec![];
        };
        entries
            .into_iter()
            .filter(|e| e.is_dir && !NOT_PROFILES.iter().any(|n| n.eq_ignore_ascii_case(&e.name)))
            .filter(|e| users.is_empty() || users.iter().any(|u| u.eq_ignore_ascii_case(&e.name)))
            .map(|e| join(&users_dir, &e.name))
            .collect()
    }

    fn hives(&mut self, users: &[String]) {
        let g = Group::Hives;
        if let Some(cfg) = self.folder(g, "Windows/System32/config")
            && let Some(entries) = self.list(g, &cfg)
        {
            for h in SYSTEM_HIVES {
                self.with_logs(g, &cfg, &entries, h);
            }
        }
        for p in self.profiles(g, users) {
            if let Some(entries) = self.list(g, &p) {
                self.with_logs(g, &p, &entries, "NTUSER.DAT");
            }
            let mut d = p.clone();
            let mut ok = true;
            for part in ["AppData", "Local", "Microsoft", "Windows"] {
                match self.child(g, &d, part, true) {
                    Some(x) => d = x,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && let Some(entries) = self.list(g, &d) {
                self.with_logs(g, &d, &entries, "UsrClass.dat");
            }
        }
    }

    fn browsers(&mut self, users: &[String]) {
        let g = Group::Browsers;
        for p in self.profiles(g, users) {
            for chromium in [
                ["AppData", "Local", "Microsoft", "Edge", "User Data"],
                ["AppData", "Local", "Google", "Chrome", "User Data"],
            ] {
                if let Some(ud) = self.walk(g, &p, &chromium)
                    && let Some(profiles) = self.list(g, &ud)
                {
                    for prof in profiles.into_iter().filter(|e| e.is_dir) {
                        let d = join(&ud, &prof.name);
                        if let Some(entries) = self.list(g, &d) {
                            self.sqlite(g, &d, &entries, "History");
                        }
                    }
                }
            }
            if let Some(fx) = self.walk(
                g,
                &p,
                &["AppData", "Roaming", "Mozilla", "Firefox", "Profiles"],
            ) && let Some(profiles) = self.list(g, &fx)
            {
                for prof in profiles.into_iter().filter(|e| e.is_dir) {
                    let d = join(&fx, &prof.name);
                    if let Some(entries) = self.list(g, &d) {
                        self.sqlite(g, &d, &entries, "places.sqlite");
                    }
                }
            }
        }
    }

    fn walk(&mut self, group: Group, from: &str, parts: &[&str]) -> Option<String> {
        let mut d = from.to_string();
        for part in parts {
            d = self.child(group, &d, part, true)?;
        }
        Some(d)
    }
}

/// Every file to collect for `groups` (volatile is not a file group and is ignored here), sorted by group and
/// then by path (case-insensitive), so two runs over the same volume list targets in the same order.
pub fn resolve(src: &dyn Source, groups: &[Group], users: &[String]) -> Vec<Resolved> {
    let mut w = Walker { src, out: vec![] };
    for g in groups {
        match g {
            Group::Volatile => {}
            Group::Hives => w.hives(users),
            Group::Evtx => {
                if let Some(d) = w.folder(*g, "Windows/System32/winevt/Logs") {
                    w.files_with(*g, &d, ".evtx");
                }
            }
            Group::Prefetch => {
                if let Some(d) = w.folder(*g, "Windows/Prefetch") {
                    w.files_with(*g, &d, ".pf");
                }
            }
            Group::Browsers => w.browsers(users),
            Group::Tasks => {
                if let Some(d) = w.folder(*g, "Windows/System32/Tasks") {
                    w.tree(*g, &d, 0);
                }
            }
        }
    }
    let key = |r: &Resolved| match r {
        Resolved::File(t) => (t.group, t.path.to_lowercase()),
        Resolved::Unlisted { group, path, .. } => (*group, path.to_lowercase()),
    };
    w.out.sort_by_key(key);
    w.out.dedup_by(|a, b| key(a) == key(b));
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::source::DirectorySource;

    fn touch(root: &std::path::Path, rel: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn resolves_every_group_case_insensitively() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for f in [
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/SYSTEM.LOG1",
            "Windows/System32/config/SAM",
            "Windows/System32/config/notahive",
            "Windows/System32/winevt/Logs/Security.evtx",
            "Windows/System32/winevt/Logs/readme.txt",
            "Windows/prefetch/CMD.EXE-0BD30981.pf",
            "Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag",
            "Windows/System32/Tasks/Updater",
            "Users/ana/NTUSER.DAT",
            "Users/ana/ntuser.dat.LOG1",
            "Users/ana/AppData/Local/Microsoft/Windows/UsrClass.dat",
            "Users/ana/AppData/Local/Microsoft/Edge/User Data/Default/History",
            "Users/ana/AppData/Local/Microsoft/Edge/User Data/Default/History-journal",
            "Users/ana/AppData/Local/Google/Chrome/User Data/Profile 1/History",
            "Users/ana/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite-wal",
            "Users/ana/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite",
            "Users/ben/NTUSER.DAT",
        ] {
            touch(r, f);
        }
        let s = DirectorySource::open(r).unwrap();
        let all = resolve(&s, &Group::ALL, &[]);
        let files: Vec<(Group, String)> = all
            .iter()
            .filter_map(|x| match x {
                Resolved::File(t) => Some((t.group, t.path.clone())),
                _ => None,
            })
            .collect();
        let has = |g, p: &str| files.iter().any(|(gg, pp)| *gg == g && pp == p);
        assert!(has(Group::Hives, "Windows/System32/config/SYSTEM.LOG1"));
        assert!(has(Group::Hives, "Users/ana/ntuser.dat.LOG1"));
        assert!(has(Group::Hives, "Users/ben/NTUSER.DAT"));
        assert!(has(
            Group::Hives,
            "Users/ana/AppData/Local/Microsoft/Windows/UsrClass.dat"
        ));
        assert!(!files.iter().any(|(_, p)| p.ends_with("notahive")));
        assert!(has(
            Group::Evtx,
            "Windows/System32/winevt/Logs/Security.evtx"
        ));
        assert!(!files.iter().any(|(_, p)| p.ends_with("readme.txt")));
        assert!(has(Group::Prefetch, "Windows/prefetch/CMD.EXE-0BD30981.pf"));
        assert!(has(
            Group::Tasks,
            "Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag"
        ));
        assert!(has(
            Group::Browsers,
            "Users/ana/AppData/Local/Microsoft/Edge/User Data/Default/History-journal"
        ));
        assert!(has(
            Group::Browsers,
            "Users/ana/AppData/Local/Google/Chrome/User Data/Profile 1/History"
        ));
        assert!(has(
            Group::Browsers,
            "Users/ana/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite-wal"
        ));
        assert_eq!(files.len(), 16);
        // --users filter
        let ben = resolve(&s, &[Group::Hives], &["BEN".into()]);
        assert_eq!(
            ben.iter()
                .filter(|x| matches!(x, Resolved::File(t) if t.path.starts_with("Users/")))
                .count(),
            1
        );
        // deterministic
        assert_eq!(all, resolve(&s, &Group::ALL, &[]));
    }
}
