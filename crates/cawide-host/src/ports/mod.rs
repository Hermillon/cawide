//! Port scanning and process attribution.

pub mod watch;

use std::collections::{BTreeSet, HashMap};

use cawide_protocol::types::ListeningPort;

/// Discovers open TCP listening ports on the host and attributes them to sessions.
pub fn scan(
    exclude_pid: Option<u32>,
    roots: &HashMap<u32, String>,
) -> Result<Vec<ListeningPort>, String> {
    let all = listeners::get_all().map_err(|e| e.to_string())?;

    // Map: port -> (addresses, Option<(pid, process_name)>)
    type PortInfo = (BTreeSet<String>, Option<(u32, String)>);
    let excluded_ports: BTreeSet<u16> = match exclude_pid {
        Some(target) => all
            .iter()
            .filter(|l| {
                l.protocol == listeners::Protocol::TCP
                    && l.state == listeners::SocketState::Listen
                    && l.process.pid == target
            })
            .map(|l| l.socket.port())
            .collect(),
        None => BTreeSet::new(),
    };

    let mut by_port: HashMap<u16, PortInfo> = HashMap::new();
    for l in all {
        if l.protocol != listeners::Protocol::TCP || l.state != listeners::SocketState::Listen {
            continue;
        }
        let port = l.socket.port();
        if excluded_ports.contains(&port) {
            continue;
        }
        let pid = l.process.pid;
        if exclude_pid == Some(pid) {
            continue;
        }
        let entry = by_port
            .entry(port)
            .or_insert_with(|| (BTreeSet::new(), None));
        entry.0.insert(l.socket.ip().to_string());

        let proc_info = (pid, l.process.name);
        match &entry.1 {
            None => entry.1 = Some(proc_info),
            Some((existing_pid, _)) if pid < *existing_pid => entry.1 = Some(proc_info),
            _ => {}
        }
    }

    let mut result = Vec::with_capacity(by_port.len());
    for (port, (addrs, proc_info)) in by_port {
        let (pid, process_name, session_id) = match proc_info {
            Some((p, name)) => {
                let sid = attribute(p, roots, parent_pid);
                (Some(p), Some(name), sid)
            }
            None => (None, None, None),
        };
        result.push(ListeningPort {
            port,
            addresses: addrs.into_iter().collect(),
            pid,
            process_name,
            session_id,
        });
    }

    result.sort_by_key(|lp| lp.port);
    Ok(result)
}

/// Climbs up process ancestry up to 64 hops to find a root process matching an active session.
pub fn attribute(
    pid: u32,
    roots: &HashMap<u32, String>,
    parent_of: impl Fn(u32) -> Option<u32>,
) -> Option<String> {
    let mut curr = pid;
    for _ in 0..64 {
        if curr == 0 || curr == 1 {
            break;
        }
        if let Some(session_id) = roots.get(&curr) {
            return Some(session_id.clone());
        }
        match parent_of(curr) {
            Some(parent) => curr = parent,
            None => break,
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: u32) -> Option<u32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: info points to a valid zeroed proc_bsdinfo buffer of size expected_size.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            expected_size,
        )
    };
    if ret == expected_size {
        Some(info.pbi_ppid)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = stat.rfind(')')? + 1;
    let rest = stat.get(after_paren..)?.trim_start();
    let ppid_str = rest.split_whitespace().nth(1)?;
    ppid_str.parse::<u32>().ok()
}

#[cfg(target_os = "windows")]
fn parent_pid(pid: u32) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut std::ffi::c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
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

    // SAFETY: OpenProcess and NtQueryInformationProcess are win32 APIs called on process ID.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
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

        let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
        let mut ret_len = 0u32;
        let status = NtQueryInformationProcess(
            handle as *mut _,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        );
        if status == 0 && pbi.inherited_from_unique_process_id != 0 {
            Some(pbi.inherited_from_unique_process_id as u32)
        } else {
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn parent_pid(_pid: u32) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute() {
        let mut roots = HashMap::new();
        roots.insert(100, "session-100".to_string());
        roots.insert(200, "session-200".to_string());

        // Tree: 100 -> 101 -> 102
        let tree: HashMap<u32, u32> = [(102, 101), (101, 100), (100, 1), (302, 301), (301, 1)]
            .into_iter()
            .collect();
        let parent_of = |pid: u32| tree.get(&pid).copied();

        // Direct child
        assert_eq!(
            attribute(101, &roots, parent_of),
            Some("session-100".to_string())
        );
        // Grandchild
        assert_eq!(
            attribute(102, &roots, parent_of),
            Some("session-100".to_string())
        );
        // Unrelated
        assert_eq!(attribute(302, &roots, parent_of), None);
        // Direct root match
        assert_eq!(
            attribute(100, &roots, parent_of),
            Some("session-100".to_string())
        );

        // 64-hop cap test: chain of 70 processes with root at 1000
        let mut deep_roots = HashMap::new();
        deep_roots.insert(1000, "session-deep".to_string());
        let mut deep_tree = HashMap::new();
        for i in 1..=70 {
            deep_tree.insert(1000 + i, 1000 + i - 1);
        }
        let deep_parent = |pid: u32| deep_tree.get(&pid).copied();

        // 60 hops: reaches root
        assert_eq!(
            attribute(1060, &deep_roots, deep_parent),
            Some("session-deep".to_string())
        );
        // 65 hops: capped at 64, does not reach root
        assert_eq!(attribute(1065, &deep_roots, deep_parent), None);
    }

    #[test]
    fn test_scan_includes_and_excludes_pid() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();
        let my_pid = std::process::id();
        let empty_roots = HashMap::new();

        let scanned = scan(None, &empty_roots).expect("scan succeeds");
        let found = scanned.iter().find(|lp| lp.port == port);
        assert!(
            found.is_some(),
            "expected port {port} in scan results: {scanned:?}"
        );
        let lp = found.unwrap();
        assert_eq!(lp.pid, Some(my_pid));
        assert!(lp.addresses.contains(&"127.0.0.1".to_string()));

        // With exclude_pid: should exclude our process's port
        let excluded = scan(Some(my_pid), &empty_roots).expect("scan succeeds");
        let found_excluded = excluded.iter().find(|lp| lp.port == port);
        assert!(
            found_excluded.is_none(),
            "port {port} should have been excluded when excluding pid {my_pid}"
        );
    }
}
