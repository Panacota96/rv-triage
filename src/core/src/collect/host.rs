//! Facts about the machine the tool runs on (FROZEN signatures for v0.1). Windows uses read-only Win32
//! queries (`windows_impl`); other platforms return what `std` can tell.

use serde::Serialize;
use std::path::Path;

/// What the report records about the collection host (`system.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SystemFacts {
    pub hostname: String,
    pub os_name: String,
    /// e.g. `10.0.26100` (Windows build), empty when unknown.
    pub os_build: String,
    pub boot_utc: Option<String>,
    /// e.g. `Romance Standard Time` / `UTC+01:00`.
    pub time_zone: String,
    /// The machine's clock when the facts were taken, local and UTC (RFC 3339).
    pub local_time: String,
    pub utc_time: String,
    /// `DOMAIN\user` running the tool.
    pub account: String,
    pub elevated: bool,
    /// `C:` on Windows; empty elsewhere.
    pub system_drive: String,
}

/// Whether the process runs elevated (Windows: token elevation; elsewhere: effective uid 0 is not checked and
/// `false` is returned, since only Windows live collection needs it).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// The system drive (`C:`), from `%SystemDrive%`; empty when unknown.
pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_default()
}

/// Whether `out` is on the same volume as `drive` (`C:`). Windows compares volume mount points
/// (`GetVolumePathNameW`); elsewhere it returns `false`.
pub fn same_volume(out: &Path, drive: &str) -> bool {
    #[cfg(windows)]
    {
        windows_impl::same_volume(out, drive)
    }
    #[cfg(not(windows))]
    {
        let _ = (out, drive);
        false
    }
}

pub fn facts() -> SystemFacts {
    #[cfg(windows)]
    {
        windows_impl::facts()
    }
    #[cfg(not(windows))]
    {
        portable_facts()
    }
}

#[allow(dead_code)]
fn portable_facts() -> SystemFacts {
    let now = jiff::ZonedDateTime::now();
    SystemFacts {
        hostname: crate::env::hostname(),
        os_name: std::env::consts::OS.into(),
        os_build: String::new(),
        boot_utc: None,
        time_zone: now.strftime("UTC%:z").to_string(),
        local_time: now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        utc_time: crate::time::utc_now(),
        account: crate::env::os_user(),
        elevated: is_elevated(),
        system_drive: system_drive(),
    }
}

#[cfg(windows)]
pub(super) mod windows_impl {
    //! Read-only Win32 queries. Nothing here writes to the machine: no files, no registry, no sessions.
    //! The small helpers (handle guard, UTF-16, FILETIME, error text) are shared with `volatile`.
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authentication::Identity::{
        GetUserNameExW, NameSamCompatible,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, QueryDosDeviceW,
    };
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW, GetTickCount64, OSVERSIONINFOEXW,
        OSVERSIONINFOW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, GetDynamicTimeZoneInformation, TIME_ZONE_ID_INVALID,
    };

    const TIME_ZONE_ID_STANDARD: u32 = 1;
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    const DRIVE_REMOTE: u32 = 4;
    /// 100-ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01.
    const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

    /// Closes a kernel handle on drop.
    pub(crate) struct Handle(pub(crate) HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: the handle was returned open by a Win32 call and is closed exactly once, here.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// NUL-terminated UTF-16.
    pub(crate) fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// UTF-16 up to the first NUL (or the whole slice).
    pub(crate) fn from_wide(buf: &[u16]) -> String {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..n])
    }

    /// Reads a NUL-terminated UTF-16 string; empty for a null pointer.
    ///
    /// # Safety
    /// `p` must be null or point to a readable, NUL-terminated UTF-16 string.
    pub(crate) unsafe fn from_pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0usize;
        // SAFETY: the caller guarantees a NUL terminator, so every read up to it is in bounds.
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    /// A FILETIME value (100 ns since 1601, UTC) as RFC 3339 UTC with milliseconds; `None` for 0 / out of range.
    pub(crate) fn filetime_utc(t: i64) -> Option<String> {
        if t <= 0 {
            return None;
        }
        let unix = t - FILETIME_UNIX_DIFF;
        let secs = unix.div_euclid(10_000_000);
        let nanos = (unix.rem_euclid(10_000_000) * 100) as u32;
        crate::collect::utc_seconds(secs).map(|s| format!("{s}.{:03}Z", nanos / 1_000_000))
    }

    /// A Win32 error code as stable English text (not the localised system message).
    pub(crate) fn os_error(code: u32) -> String {
        let text = match code {
            2 => "not found",
            3 => "path not found",
            5 => "access denied",
            6 => "invalid handle",
            32 => "sharing violation",
            87 => "invalid parameter",
            122 => "buffer too small",
            1060 => "service does not exist",
            1168 => "not found",
            1332 => "account name not mapped",
            _ => "Windows error",
        };
        format!("{} (error {})", text, code)
    }

    /// The calling thread's last Win32 error, as [`os_error`] text.
    pub(crate) fn last_error() -> String {
        // SAFETY: GetLastError only reads the calling thread's last-error value.
        os_error(unsafe { GetLastError() })
    }

    pub fn is_elevated() -> bool {
        let mut tok: HANDLE = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing; `tok` is a valid out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return false;
        }
        let tok = Handle(tok);
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        // SAFETY: `e` is a TOKEN_ELEVATION of the size passed; `len` is a valid out pointer; the token is open.
        let ok = unsafe {
            GetTokenInformation(
                tok.0,
                TokenElevation,
                (&mut e as *mut TOKEN_ELEVATION).cast::<c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        ok != 0 && e.TokenIsElevated != 0
    }

    /// `\\server\share\...` or `\\?\UNC\server\share\...`: a network path, never the system volume.
    pub(crate) fn is_network_path(s: &str) -> bool {
        let up = s.to_ascii_uppercase();
        up.starts_with(r"\\?\UNC\")
            || (s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\"))
    }

    /// The target of a `subst` drive letter (`X:` → `C:\folder`), when `drive` is one.
    fn subst_target(drive: &str) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let name = wide(std::ffi::OsStr::new(drive));
        // SAFETY: `name` is NUL-terminated; `buf` is writable for the length passed.
        let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return None;
        }
        from_wide(&buf).strip_prefix(r"\??\").map(str::to_string)
    }

    /// The mount point (`C:\` or a folder) of the volume holding an existing `p`.
    fn volume_path(p: &Path) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let name = wide(p.as_os_str());
        // SAFETY: `name` is NUL-terminated; `buf` is writable for the length passed.
        let ok = unsafe { GetVolumePathNameW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        (ok != 0).then(|| from_wide(&buf))
    }

    /// `\\?\Volume{GUID}\` for a mount point, when it is a local volume.
    fn volume_guid(mount: &str) -> Option<String> {
        let mut buf = vec![0u16; 64];
        let name = wide(std::ffi::OsStr::new(mount));
        // SAFETY: `name` is NUL-terminated; `buf` is writable for the length passed.
        let ok = unsafe {
            GetVolumeNameForVolumeMountPointW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        (ok != 0).then(|| from_wide(&buf))
    }

    fn is_remote(mount: &str) -> bool {
        let name = wide(std::ffi::OsStr::new(mount));
        // SAFETY: `name` is NUL-terminated.
        unsafe { GetDriveTypeW(name.as_ptr()) == DRIVE_REMOTE }
    }

    /// Drops a `\\?\` prefix on drive paths and resolves `subst` drives (`X:\out` on `subst X: C:\f` is
    /// `C:\f\out`).
    fn normalise(s: &str) -> String {
        let mut s = match s.strip_prefix(r"\\?\") {
            Some(rest) if rest.len() >= 2 && rest.as_bytes()[1] == b':' => rest.to_string(),
            _ => s.to_string(),
        };
        for _ in 0..4 {
            if s.len() < 2 || s.as_bytes()[1] != b':' {
                break;
            }
            match subst_target(&s[..2]) {
                Some(t) => s = format!("{}{}", t.trim_end_matches('\\'), &s[2..]),
                None => break,
            }
        }
        s
    }

    pub fn same_volume(out: &Path, drive: &str) -> bool {
        if drive.is_empty() {
            return false;
        }
        let abs = std::path::absolute(out).unwrap_or_else(|_| out.to_path_buf());
        let s = normalise(&abs.to_string_lossy());
        if is_network_path(&s) {
            return false;
        }
        // The output folder may not exist yet: its nearest existing ancestor is on the same volume.
        let p = std::path::PathBuf::from(&s);
        let Some(existing) = p
            .ancestors()
            .find(|a| !a.as_os_str().is_empty() && a.exists())
        else {
            return false;
        };
        let root = format!("{}\\", drive.trim_end_matches('\\'));
        let (Some(a), Some(b)) = (volume_path(existing), volume_path(Path::new(&root))) else {
            // No volume information: compare drive letters.
            return s.len() >= 2
                && root.len() >= 2
                && s.is_char_boundary(2)
                && root.is_char_boundary(2)
                && s[..2].eq_ignore_ascii_case(&root[..2]);
        };
        if is_remote(&a) || is_network_path(&a) {
            return false;
        }
        match (volume_guid(&a), volume_guid(&b)) {
            (Some(x), Some(y)) => x.eq_ignore_ascii_case(&y),
            _ => a.to_lowercase() == b.to_lowercase(),
        }
    }

    fn hostname() -> Option<String> {
        let mut n = 0u32;
        // SAFETY: a null buffer with size 0 only asks for the required size (UTF-16 units, with the NUL).
        unsafe { GetComputerNameExW(ComputerNameDnsHostname, null_mut(), &mut n) };
        if n == 0 {
            return None;
        }
        let mut buf = vec![0u16; n as usize + 1];
        let mut n = buf.len() as u32;
        // SAFETY: `buf` is writable for `n` units.
        let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut n) };
        (ok != 0).then(|| from_wide(&buf)).filter(|s| !s.is_empty())
    }

    fn account() -> Option<String> {
        let mut buf = vec![0u16; 512];
        let mut n = buf.len() as u32;
        // SAFETY: `buf` is writable for `n` units; `n` is a valid in/out pointer.
        let ok = unsafe { GetUserNameExW(NameSamCompatible, buf.as_mut_ptr(), &mut n) };
        ok.then(|| from_wide(&buf)).filter(|s| !s.is_empty())
    }

    /// (`Windows 11`, `10.0.26100`) from RtlGetVersion (not subject to the compatibility shims of GetVersionEx).
    fn os_version() -> Option<(String, String)> {
        // SAFETY: OSVERSIONINFOEXW is plain data; all-zero is a valid value.
        let mut v: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
        v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        // SAFETY: `v` is an OSVERSIONINFOEXW whose size field says so; RtlGetVersion accepts the EX layout.
        let st =
            unsafe { RtlGetVersion((&mut v as *mut OSVERSIONINFOEXW).cast::<OSVERSIONINFOW>()) };
        if st < 0 {
            return None;
        }
        let workstation = v.wProductType == 1;
        let name = match (v.dwMajorVersion, workstation) {
            (10, true) if v.dwBuildNumber >= 22000 => "Windows 11".to_string(),
            (10, true) => "Windows 10".to_string(),
            (_, false) => "Windows Server".to_string(),
            (maj, true) => format!("Windows {}.{}", maj, v.dwMinorVersion),
        };
        Some((
            name,
            format!(
                "{}.{}.{}",
                v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber
            ),
        ))
    }

    /// (time zone key name, current bias in minutes: UTC = local + bias).
    fn time_zone() -> Option<(String, i32)> {
        // SAFETY: DYNAMIC_TIME_ZONE_INFORMATION is plain data; all-zero is a valid value.
        let mut tz: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `tz` is a valid, writable DYNAMIC_TIME_ZONE_INFORMATION.
        let id = unsafe { GetDynamicTimeZoneInformation(&mut tz) };
        if id == TIME_ZONE_ID_INVALID {
            return None;
        }
        let bias = tz.Bias
            + match id {
                TIME_ZONE_ID_STANDARD => tz.StandardBias,
                TIME_ZONE_ID_DAYLIGHT => tz.DaylightBias,
                _ => 0,
            };
        Some((from_wide(&tz.TimeZoneKeyName), bias))
    }

    /// `UTC+01:00` for a bias of -60 minutes.
    pub(crate) fn utc_offset_text(bias: i32) -> String {
        let off = -bias;
        let sign = if off < 0 { '-' } else { '+' };
        format!("UTC{}{:02}:{:02}", sign, off.abs() / 60, off.abs() % 60)
    }

    /// (boot time, local time, UTC time) texts of the instant `now`, `up_ms` after the boot, at a zone `bias`
    /// (minutes west of UTC, Win32 sign): `2026-11-15T09:46:40Z`, `2026-11-15T10:46:40.123+01:00`,
    /// `2026-11-15T09:46:40.123Z`.
    pub(crate) fn clock_texts(
        now: std::time::SystemTime,
        up_ms: u64,
        bias: i32,
    ) -> (Option<String>, String, String) {
        let (secs, nanos) = crate::collect::unix_parts(now);
        // Milliseconds since the kernel started (sleep included; with Fast Startup, since the last full boot).
        let boot_utc = i64::try_from(up_ms).ok().and_then(|ms| {
            let boot =
                i128::from(secs) * 1_000_000_000 + i128::from(nanos) - i128::from(ms) * 1_000_000;
            let boot_secs = i64::try_from(boot.div_euclid(1_000_000_000)).ok()?;
            crate::collect::utc_seconds(boot_secs).map(|s| format!("{s}Z"))
        });
        // A zone more than a day off UTC is not a zone: written as UTC, as always.
        let offset = Some(-bias * 60)
            .filter(|o| -86_400 < *o && *o < 86_400)
            .unwrap_or(0);
        let local = crate::collect::utc_seconds(secs + i64::from(offset)).unwrap_or_default();
        let (sign, off) = (if offset < 0 { '-' } else { '+' }, offset.unsigned_abs());
        (
            boot_utc,
            format!(
                "{local}.{:03}{sign}{:02}:{:02}",
                nanos / 1_000_000,
                off / 3600,
                off % 3600 / 60
            ),
            crate::time::utc_millis(now),
        )
    }

    pub fn facts() -> SystemFacts {
        let now = std::time::SystemTime::now();
        // SAFETY: GetTickCount64 has no preconditions.
        let up_ms = unsafe { GetTickCount64() };
        let (key, bias) = time_zone().unwrap_or_else(|| {
            let off = jiff::ZonedDateTime::now().offset().seconds() / 60;
            (String::new(), -off)
        });
        let (boot_utc, local_time, utc_time) = clock_texts(now, up_ms, bias);
        let offset_text = utc_offset_text(bias);
        let time_zone = if key.is_empty() {
            offset_text
        } else {
            format!("{} ({})", key, offset_text)
        };
        let (os_name, os_build) = os_version().unwrap_or_else(|| ("Windows".into(), String::new()));
        SystemFacts {
            hostname: hostname().unwrap_or_else(crate::env::hostname),
            os_name,
            os_build,
            boot_utc,
            time_zone,
            local_time,
            utc_time,
            account: account().unwrap_or_else(crate::env::os_user),
            elevated: is_elevated(),
            system_drive: system_drive(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn facts_are_filled() {
            let f = facts();
            assert!(!f.hostname.is_empty());
            assert!(!f.os_build.is_empty());
            assert!(f.os_name.starts_with("Windows"));
            assert!(!f.system_drive.is_empty());
            assert!(!f.account.is_empty());
            assert!(f.utc_time.ends_with('Z'));
            assert!(f.boot_utc.as_deref().is_some_and(|b| b.ends_with('Z')));
            assert!(f.time_zone.contains("UTC"));
            // Same instant, two notations.
            let l: jiff::Timestamp = f.local_time.parse().unwrap();
            let u: jiff::Timestamp = f.utc_time.parse().unwrap();
            assert_eq!(l, u);
        }

        #[test]
        fn elevation_check_returns() {
            let _ = is_elevated();
        }

        #[test]
        fn volumes() {
            let sd = system_drive();
            assert!(!sd.is_empty());
            assert!(same_volume(Path::new(&format!("{}\\", sd)), &sd));
            assert!(same_volume(Path::new(&format!("{}\\Windows", sd)), &sd));
            assert!(same_volume(Path::new(&format!(r"\\?\{}\Windows", sd)), &sd));
            let tmp = std::env::temp_dir();
            if tmp
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with(&sd.to_ascii_uppercase())
            {
                let missing = tmp.join("rv-triage-no-such-dir").join("sub");
                assert!(!missing.exists());
                assert!(same_volume(&missing, &sd));
            }
            assert!(!same_volume(Path::new(r"\\server\share\x"), &sd));
            assert!(!same_volume(Path::new(r"\\?\UNC\server\share\x"), &sd));
            assert!(!same_volume(Path::new(r"C:\x"), ""));
        }

        #[test]
        fn helpers() {
            assert_eq!(utc_offset_text(-60), "UTC+01:00");
            assert_eq!(utc_offset_text(300), "UTC-05:00");
            assert_eq!(utc_offset_text(-330), "UTC+05:30");
            assert_eq!(utc_offset_text(0), "UTC+00:00");
            assert_eq!(
                filetime_utc(FILETIME_UNIX_DIFF).as_deref(),
                Some("1970-01-01T00:00:00.000Z")
            );
            assert_eq!(filetime_utc(0), None);
            assert!(is_network_path(r"\\srv\s"));
            assert!(is_network_path(r"\\?\unc\srv\s"));
            assert!(!is_network_path(r"\\?\C:\x"));
            assert_eq!(os_error(5), "access denied (error 5)");
        }
    }
}
