use std::path::PathBuf;

const MAX_ARGV: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcInfo {
    pub argv: Vec<String>,
    pub exe: Option<PathBuf>,
}

#[derive(Default)]
pub struct ProcScratch {
    #[cfg(target_os = "macos")]
    args: Vec<u8>,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_procargs2(buf: &[u8]) -> Vec<String> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let mut argc_bytes = [0u8; 4];
    argc_bytes.copy_from_slice(&buf[..4]);
    let argc = i32::from_ne_bytes(argc_bytes);
    if argc <= 0 {
        return Vec::new();
    }

    let mut pos = 4;
    // Skip exec path up to its NUL byte.
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    if pos >= buf.len() {
        return Vec::new();
    }
    pos += 1; // skip NUL byte

    // Skip following NUL padding bytes.
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }

    let target_count = (argc as usize).min(MAX_ARGV);
    let mut args = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        if pos >= buf.len() {
            break;
        }
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        let arg_bytes = &buf[start..pos];
        args.push(String::from_utf8_lossy(arg_bytes).into_owned());
        if pos < buf.len() && buf[pos] == 0 {
            pos += 1;
        }
    }
    args
}

#[cfg(target_os = "macos")]
pub fn proc_cwd(pid: i32) -> Option<PathBuf> {
    let mut info: libc::proc_vnodepathinfo = unsafe {
        // SAFETY: proc_vnodepathinfo is a plain C struct of primitive types; zero-initialization is valid.
        std::mem::zeroed()
    };
    let expected_size = std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
    let ret = unsafe {
        // SAFETY: info points to a valid, zeroed proc_vnodepathinfo buffer of size expected_size.
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            expected_size,
        )
    };
    if ret != expected_size {
        return None;
    }

    let raw_bytes = unsafe {
        // SAFETY: vip_path is a fixed-size buffer within info, which was initialized and populated by proc_pidinfo.
        std::slice::from_raw_parts(
            info.pvi_cdir.vip_path.as_ptr() as *const u8,
            std::mem::size_of_val(&info.pvi_cdir.vip_path),
        )
    };
    let nul_pos = raw_bytes.iter().position(|&b| b == 0)?;
    if nul_pos == 0 {
        return None;
    }
    use std::os::unix::ffi::OsStrExt;
    let bytes = &raw_bytes[..nul_pos];
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn proc_exe_macos(pid: i32) -> Option<PathBuf> {
    let mut buf = [0u8; 4096];
    let ret = unsafe {
        // SAFETY: buf is a valid stack buffer of 4096 bytes.
        libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
    };
    if ret <= 0 {
        return None;
    }
    let len = (ret as usize).min(buf.len());
    let path_bytes = &buf[..len];
    let nul_pos = path_bytes.iter().position(|&b| b == 0).unwrap_or(len);
    if nul_pos == 0 {
        return None;
    }
    use std::os::unix::ffi::OsStrExt;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        &path_bytes[..nul_pos],
    )))
}

#[cfg(target_os = "macos")]
pub fn proc_info(pid: i32, scratch: &mut ProcScratch) -> Option<ProcInfo> {
    let exe = proc_exe_macos(pid);

    if scratch.args.is_empty() {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut argmax: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        let ret = unsafe {
            // SAFETY: mib has 2 valid elements, argmax and size are valid pointers.
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                &mut argmax as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        let cap = if ret == 0 && argmax > 0 {
            argmax as usize
        } else {
            262_144
        };
        scratch.args.resize(cap, 0);
    }

    let argv = {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size = scratch.args.len();
        let ret = unsafe {
            // SAFETY: mib has 3 valid elements, scratch.args has at least size bytes allocated.
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                scratch.args.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 && size > 0 && size <= scratch.args.len() {
            parse_procargs2(&scratch.args[..size])
        } else {
            Vec::new()
        }
    };

    if argv.is_empty() && exe.is_none() {
        None
    } else {
        Some(ProcInfo { argv, exe })
    }
}

#[cfg(target_os = "linux")]
pub fn proc_cwd(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .filter(|p| p.exists())
}

#[cfg(target_os = "linux")]
pub fn proc_info(pid: i32, _scratch: &mut ProcScratch) -> Option<ProcInfo> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let argv = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(data) => data
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .take(MAX_ARGV)
            .map(|slice| String::from_utf8_lossy(slice).into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    if argv.is_empty() && exe.is_none() {
        None
    } else {
        Some(ProcInfo { argv, exe })
    }
}

#[cfg(target_os = "windows")]
pub fn proc_cwd(pid: i32) -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut std::ffi::c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut std::ffi::c_void,
            process_information_class: u32,
            process_information: *mut std::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            0,
            pid as u32,
        );
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _guard = HandleGuard(handle);

        let mut is_wow64: i32 = 0;
        if IsWow64Process(handle, &mut is_wow64) == 0 || is_wow64 != 0 {
            return None;
        }

        let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
        let mut ret_len = 0u32;
        let status = NtQueryInformationProcess(
            handle as *mut _,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        );
        if status != 0 || pbi.peb_base_address.is_null() {
            return None;
        }

        // In 64-bit Windows PEB: ProcessParameters offset is at 0x20
        let mut proc_params_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut bytes_read = 0usize;
        let peb_params_addr = (pbi.peb_base_address as usize + 0x20) as *const std::ffi::c_void;
        if ReadProcessMemory(
            handle,
            peb_params_addr,
            &mut proc_params_ptr as *mut _ as *mut _,
            std::mem::size_of::<*mut std::ffi::c_void>(),
            &mut bytes_read,
        ) == 0
            || proc_params_ptr.is_null()
        {
            return None;
        }

        // CurrentDirectory is at offset 0x38 in RTL_USER_PROCESS_PARAMETERS
        // CurrentDirectory.DosPath is a UNICODE_STRING at offset 0x38 (Length: u16, MaximumLength: u16, Buffer: *mut u16)
        let dos_path_addr = (proc_params_ptr as usize + 0x38) as *const std::ffi::c_void;
        let mut dos_path_us = std::mem::zeroed::<UnicodeString>();
        if ReadProcessMemory(
            handle,
            dos_path_addr,
            &mut dos_path_us as *mut _ as *mut _,
            std::mem::size_of::<UnicodeString>(),
            &mut bytes_read,
        ) == 0
            || dos_path_us.buffer.is_null()
            || dos_path_us.length == 0
        {
            return None;
        }

        let char_count = (dos_path_us.length / 2) as usize;
        if char_count > 32768 {
            return None;
        }
        let mut path_buf = vec![0u16; char_count];
        if ReadProcessMemory(
            handle,
            dos_path_us.buffer as *const std::ffi::c_void,
            path_buf.as_mut_ptr() as *mut _,
            dos_path_us.length as usize,
            &mut bytes_read,
        ) == 0
        {
            return None;
        }

        let path_str = String::from_utf16_lossy(&path_buf);
        let path = PathBuf::from(path_str.trim_end_matches(['\\', '/']));
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
pub fn proc_info(pid: i32, _scratch: &mut ProcScratch) -> Option<ProcInfo> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut std::ffi::c_void,
            process_information_class: u32,
            process_information: *mut std::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _guard = HandleGuard(handle);

        // 1. Full executable path
        let mut exe_buf = [0u16; 4096];
        let mut exe_len = exe_buf.len() as u32;
        let exe = if QueryFullProcessImageNameW(handle, 0, exe_buf.as_mut_ptr(), &mut exe_len) != 0
            && exe_len > 0
        {
            let s = String::from_utf16_lossy(&exe_buf[..exe_len as usize]);
            Some(PathBuf::from(s))
        } else {
            None
        };

        // 2. Command line via NtQueryInformationProcess(ProcessCommandLineInformation = 60)
        let mut buf_size = 1024u32;
        let mut cmd_buf: Vec<u8> = vec![0u8; buf_size as usize];
        let mut ret_len = 0u32;
        let mut status = NtQueryInformationProcess(
            handle as *mut _,
            60, // ProcessCommandLineInformation
            cmd_buf.as_mut_ptr() as *mut _,
            buf_size,
            &mut ret_len,
        );
        if status != 0 && ret_len > buf_size {
            buf_size = ret_len + 32;
            cmd_buf.resize(buf_size as usize, 0);
            status = NtQueryInformationProcess(
                handle as *mut _,
                60,
                cmd_buf.as_mut_ptr() as *mut _,
                buf_size,
                &mut ret_len,
            );
        }

        let mut argv = Vec::new();
        if status == 0 && ret_len >= std::mem::size_of::<UnicodeString>() as u32 {
            let us = &*(cmd_buf.as_ptr() as *const UnicodeString);
            if !us.buffer.is_null() && us.length > 0 {
                let char_count = (us.length / 2) as usize;
                let mut wide_chars = Vec::with_capacity(char_count + 1);
                let slice = std::slice::from_raw_parts(us.buffer, char_count);
                wide_chars.extend_from_slice(slice);
                wide_chars.push(0); // NUL terminator

                let mut argc = 0i32;
                let argv_ptr = CommandLineToArgvW(wide_chars.as_ptr(), &mut argc);
                if !argv_ptr.is_null() && argc > 0 {
                    struct LocalFreeGuard(*mut *mut u16);
                    impl Drop for LocalFreeGuard {
                        fn drop(&mut self) {
                            unsafe {
                                LocalFree(self.0 as *mut _);
                            }
                        }
                    }
                    let _argv_guard = LocalFreeGuard(argv_ptr);

                    let take_n = (argc as usize).min(MAX_ARGV);
                    for i in 0..take_n {
                        let arg_w = *argv_ptr.add(i);
                        if !arg_w.is_null() {
                            let mut len = 0;
                            while *arg_w.add(len) != 0 {
                                len += 1;
                            }
                            let slice = std::slice::from_raw_parts(arg_w, len);
                            argv.push(String::from_utf16_lossy(slice));
                        }
                    }
                }
            }
        }

        if argv.is_empty() && exe.is_none() {
            None
        } else {
            Some(ProcInfo { argv, exe })
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn proc_cwd(_pid: i32) -> Option<PathBuf> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn proc_info(_pid: i32, _scratch: &mut ProcScratch) -> Option<ProcInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_cwd_self() {
        let current = std::env::current_dir()
            .ok()
            .and_then(|p| p.canonicalize().ok());
        let cwd = proc_cwd(std::process::id() as i32);
        assert_eq!(cwd, current);
    }

    #[cfg(unix)]
    #[test]
    fn test_proc_child() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .current_dir(temp.path())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        let mut scratch = ProcScratch::default();
        let mut info = None;
        for _ in 0..50 {
            if let Some(i) = proc_info(pid, &mut scratch) {
                if !i.argv.is_empty() {
                    info = Some(i);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let cwd = proc_cwd(pid);
        let _ = child.kill();
        let _ = child.wait();

        let canonical_temp = temp.path().canonicalize().ok();
        assert_eq!(cwd, canonical_temp);
        let info = info.expect("proc info");
        assert!(!info.argv.is_empty());
        assert_eq!(info.argv[0], "sleep");
        if info.argv.len() > 1 {
            assert_eq!(info.argv[1], "30");
        }
        assert!(info.exe.is_some());
    }

    #[test]
    fn test_parse_procargs2_handcrafted() {
        let mut buf = Vec::new();
        let argc = 5i32;
        buf.extend_from_slice(&argc.to_ne_bytes());
        buf.extend_from_slice(b"/usr/local/bin/node\0");
        buf.extend_from_slice(b"\0\0\0");
        buf.extend_from_slice(b"node\0");
        buf.extend_from_slice(b"/x/cli.js\0");
        buf.extend_from_slice(b"--y\0");
        buf.extend_from_slice(b"a\0");
        buf.extend_from_slice(b"b\0");

        let args = parse_procargs2(&buf);
        assert_eq!(args, vec!["node", "/x/cli.js", "--y", "a"]);

        let truncated = &buf[..8];
        let args_trunc = parse_procargs2(truncated);
        assert!(args_trunc.is_empty());

        let empty = parse_procargs2(&[]);
        assert!(empty.is_empty());

        let mut zero_argc = Vec::new();
        zero_argc.extend_from_slice(&0i32.to_ne_bytes());
        zero_argc.extend_from_slice(b"/bin/ls\0ls\0");
        assert!(parse_procargs2(&zero_argc).is_empty());
    }
}
