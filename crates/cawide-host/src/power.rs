//! Power assertion preventing idle sleep during daemon execution (macOS & Windows).
#[cfg(target_os = "macos")]
mod sys {
    use std::ffi::c_void;

    pub type CFAllocatorRef = *const c_void;
    pub type CFStringRef = *const c_void;
    pub type CFTypeRef = *const c_void;
    pub type CFStringEncoding = u32;
    pub type IOReturn = i32;
    pub type IOPMAssertionID = u32;
    pub type IOPMAssertionLevel = u32;

    pub const K_CF_STRING_ENCODING_UTF8: CFStringEncoding = 0x0800_0100;
    pub const K_IO_RETURN_SUCCESS: IOReturn = 0;
    pub const K_IOPM_ASSERTION_LEVEL_ON: IOPMAssertionLevel = 255;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        pub fn IOPMAssertionCreateWithName(
            assertion_type: CFStringRef,
            assertion_level: IOPMAssertionLevel,
            assertion_detail: CFStringRef,
            assertion_id: *mut IOPMAssertionID,
        ) -> IOReturn;

        pub fn IOPMAssertionRelease(assertion_id: IOPMAssertionID) -> IOReturn;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        pub fn CFStringCreateWithCString(
            alloc: CFAllocatorRef,
            c_str: *const std::ffi::c_char,
            encoding: CFStringEncoding,
        ) -> CFStringRef;

        pub fn CFRelease(cf: CFTypeRef);
    }
}

#[cfg(target_os = "windows")]
mod sys {
    use windows_sys::Win32::System::Power::{
        SetThreadExecutionState, ES_AWAYMODE_REQUIRED, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
    };
    pub fn acquire() -> bool {
        // SAFETY: SetThreadExecutionState is a win32 API call to set thread power execution flags.
        unsafe {
            let ret =
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
            if ret != 0 {
                return true;
            }
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) != 0
        }
    }
    pub fn release() {
        // SAFETY: SetThreadExecutionState(ES_CONTINUOUS) resets the power state back to default.
        unsafe {
            SetThreadExecutionState(ES_CONTINUOUS);
        }
    }
}

/// RAII guard releasing the power assertion on drop.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct PowerAssertionGuard(u32);

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct PowerAssertionGuard(bool);

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[derive(Debug)]
pub struct PowerAssertionGuard(#[allow(dead_code)] u32);
#[cfg(target_os = "macos")]
impl Drop for PowerAssertionGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: self.0 is an active assertion ID returned by IOPMAssertionCreateWithName.
            let ret = unsafe { sys::IOPMAssertionRelease(self.0) };
            if ret == sys::K_IO_RETURN_SUCCESS {
                tracing::info!(assertion_id = self.0, "macOS power assertion released");
            } else {
                tracing::warn!(
                    assertion_id = self.0,
                    ret,
                    "failed to release power assertion"
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for PowerAssertionGuard {
    fn drop(&mut self) {
        if self.0 {
            sys::release();
            tracing::info!("Windows power assertion released");
        }
    }
}

/// Prevents the host machine from entering idle sleep while the daemon is running.
pub fn prevent_idle_sleep(reason: &str) -> Option<PowerAssertionGuard> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::ptr;

        let assertion_type = CString::new("PreventUserIdleSystemSleep").ok()?;
        let reason_c = CString::new(reason).ok()?;

        // SAFETY: CFStringCreateWithCString is called with a valid null-terminated C string and UTF-8 encoding.
        let cf_type = unsafe {
            sys::CFStringCreateWithCString(
                ptr::null(),
                assertion_type.as_ptr(),
                sys::K_CF_STRING_ENCODING_UTF8,
            )
        };
        if cf_type.is_null() {
            return None;
        }

        // SAFETY: CFStringCreateWithCString is called with a valid null-terminated C string and UTF-8 encoding.
        let cf_detail = unsafe {
            sys::CFStringCreateWithCString(
                ptr::null(),
                reason_c.as_ptr(),
                sys::K_CF_STRING_ENCODING_UTF8,
            )
        };
        if cf_detail.is_null() {
            // SAFETY: cf_type is non-null and was allocated by CFStringCreateWithCString above.
            unsafe { sys::CFRelease(cf_type) };
            return None;
        }

        let mut assertion_id: sys::IOPMAssertionID = 0;
        // SAFETY: Both CFStrings are valid non-null pointers, and assertion_id is a valid out-pointer.
        let ret = unsafe {
            sys::IOPMAssertionCreateWithName(
                cf_type,
                sys::K_IOPM_ASSERTION_LEVEL_ON,
                cf_detail,
                &mut assertion_id,
            )
        };

        // SAFETY: Releasing the temporary CFString instances allocated in this function.
        unsafe {
            sys::CFRelease(cf_detail);
            sys::CFRelease(cf_type);
        }

        if ret == sys::K_IO_RETURN_SUCCESS {
            tracing::info!(assertion_id, "macOS power assertion acquired ({reason})");
            Some(PowerAssertionGuard(assertion_id))
        } else {
            tracing::warn!(ret, "failed to acquire power assertion");
            None
        }
    }
    #[cfg(target_os = "windows")]
    {
        if sys::acquire() {
            tracing::info!("Windows power assertion acquired ({reason})");
            Some(PowerAssertionGuard(true))
        } else {
            tracing::warn!("failed to acquire Windows power assertion");
            None
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = reason;
        None
    }
}
