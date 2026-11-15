//! Command-line arguments of the GUI executable: input paths (a folder or image dropped on the .exe icon),
//! `--case-dir DIR` / `--case-dir=DIR` (RV Hub opens every tool on a case folder; a collection does not use one)
//! and `--elevation-requested-at=UTC`, which "Restart as administrator" passes to the elevated window.
//! Also the relaunch itself ([`relaunch_elevated`]).

use std::ffi::OsString;
use std::path::PathBuf;

/// The option RV Hub uses to preset the case folder.
pub const CASE_DIR_FLAG: &str = "--case-dir";

/// Passed by "Restart as administrator" to the elevated window: the time of the click.
pub const ELEVATION_FLAG: &str = "--elevation-requested-at";

/// What the GUI was started with.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    /// `--case-dir` value (the last one wins when repeated).
    pub case_dir: Option<PathBuf>,
    /// Every other argument, in order: files or folders to pre-load.
    pub inputs: Vec<PathBuf>,
    /// Problems with the arguments (ignored, shown to the user and recorded in the audit log).
    pub notes: Vec<String>,
    /// `--elevation-requested-at=UTC`: this window replaces one where "Restart as administrator" was clicked.
    pub elevation_requested_at: Option<String>,
}

/// A UTC time as `time::utc_now` writes it (digits, `-`, `:`, `.`, `T`, `Z`; at most 40 characters).
fn plausible_utc(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 40
        && v.ends_with('Z')
        && v.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z'))
}

/// Splits the GUI arguments (without the program name, and without a leading `worker`, which `main`
/// handles first). `--case-dir` without a value (last argument, empty, or followed by another `--`
/// option) is ignored with a note; it is never taken as an input path.
pub fn parse_launch_args(args: impl IntoIterator<Item = OsString>) -> LaunchArgs {
    let mut out = LaunchArgs::default();
    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
        let text = arg.to_string_lossy();
        let value = if text == CASE_DIR_FLAG {
            match it.peek() {
                Some(next) if next.to_string_lossy().starts_with("--") => None,
                // An empty value is consumed (it is not an input either).
                Some(_) => it.next().filter(|v| !v.is_empty()),
                None => None,
            }
        } else if let Some(v) = text.strip_prefix("--case-dir=") {
            Some(OsString::from(v)).filter(|v| !v.is_empty())
        } else if let Some(v) = text.strip_prefix(&format!("{}=", ELEVATION_FLAG)) {
            if plausible_utc(v) {
                out.elevation_requested_at = Some(v.to_string());
            } else {
                out.notes.push(format!(
                    "{} with an unreadable time: ignored",
                    ELEVATION_FLAG
                ));
            }
            continue;
        } else {
            out.inputs.push(PathBuf::from(arg));
            continue;
        };
        match value {
            Some(v) => out.case_dir = Some(PathBuf::from(v)),
            None => out
                .notes
                .push(format!("{} given without a folder: ignored", CASE_DIR_FLAG)),
        }
    }
    out
}

/// Starts this executable again through the UAC prompt (`ShellExecuteW` with the `runas` verb), passing the
/// time of the click. `Err` when the prompt was declined or the relaunch could not start; the caller keeps the
/// window open then.
pub fn relaunch_elevated(requested_at_utc: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current executable: {}", e))?;
    let params = format!("{}={}", ELEVATION_FLAG, requested_at_utc);
    shell_runas(&exe, &params)
}

#[cfg(windows)]
fn shell_runas(exe: &std::path::Path, params: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }
    let verb = wide(std::ffi::OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let params = wide(std::ffi::OsStr::new(params));
    // SAFETY: every pointer is a NUL-terminated UTF-16 buffer that outlives the call; a null window handle
    // and a null directory are allowed by ShellExecuteW.
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Values above 32 mean success; 5 (SE_ERR_ACCESSDENIED) is the declined UAC prompt.
    let code = r as isize;
    if code > 32 {
        Ok(())
    } else if code == 5 {
        Err("the administrator prompt was declined".into())
    } else {
        Err(format!("ShellExecuteW failed (code {})", code))
    }
}

#[cfg(not(windows))]
fn shell_runas(_exe: &std::path::Path, _params: &str) -> Result<(), String> {
    Err("restarting as administrator is only available on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> LaunchArgs {
        parse_launch_args(args.iter().map(OsString::from))
    }

    #[test]
    fn case_dir_then_inputs() {
        let a = parse(&["--case-dir", "X", "a.pdf"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("X")));
        assert_eq!(a.inputs, vec![PathBuf::from("a.pdf")]);
        assert!(a.notes.is_empty());
    }

    #[test]
    fn case_dir_with_equals_sign() {
        let a = parse(&["--case-dir=X"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("X")));
        assert!(a.inputs.is_empty() && a.notes.is_empty());
        let a = parse(&["b.pdf", "--case-dir=E:\\CASE 014"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("E:\\CASE 014")));
        assert_eq!(a.inputs, vec![PathBuf::from("b.pdf")]);
    }

    #[test]
    fn without_the_flag_every_argument_is_an_input() {
        let a = parse(&["a.pdf", "D:\\evidence"]);
        assert_eq!(a.case_dir, None);
        assert_eq!(
            a.inputs,
            vec![PathBuf::from("a.pdf"), PathBuf::from("D:\\evidence")]
        );
        assert!(a.notes.is_empty());
        assert_eq!(parse(&[]), LaunchArgs::default());
    }

    #[test]
    fn flag_without_a_value_is_ignored_with_a_note() {
        for args in [
            &["a.pdf", "--case-dir"][..],
            &["--case-dir=", "a.pdf"][..],
            &["--case-dir", "", "a.pdf"][..],
        ] {
            let a = parse(args);
            assert_eq!(a.case_dir, None, "{:?}", args);
            assert_eq!(a.inputs, vec![PathBuf::from("a.pdf")], "{:?}", args);
            assert_eq!(a.notes.len(), 1, "{:?}", args);
            assert!(a.notes[0].contains("--case-dir"));
        }
        // Followed by another option: the option is not swallowed as the folder.
        let a = parse(&["--case-dir", "--case-dir=Y"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("Y")));
        assert_eq!(a.notes.len(), 1);
    }

    #[test]
    fn elevation_time_is_read_and_checked() {
        let a = parse(&["--elevation-requested-at=2026-11-15T10:00:00.123Z"]);
        assert_eq!(
            a.elevation_requested_at.as_deref(),
            Some("2026-11-15T10:00:00.123Z")
        );
        assert!(a.inputs.is_empty() && a.notes.is_empty());
        let a = parse(&["--elevation-requested-at=now; rm -rf"]);
        assert_eq!(a.elevation_requested_at, None);
        assert_eq!(a.notes.len(), 1);
    }

    #[test]
    fn last_case_dir_wins() {
        let a = parse(&["--case-dir", "X", "--case-dir", "Y"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("Y")));
    }
}
