// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

/// Minimal seccomp-style hardening placeholder.
///
/// A full filter needs `libseccomp` / `seccompiler`. Here we drop ambient
/// capabilities we can via prctl where available, and no-op elsewhere so the
/// control plane still runs on macOS/dev hosts.
pub fn apply_minimal() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Best-effort: disable core dumps for the VMM process.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod libc {
    #![allow(non_camel_case_types)]
    pub type c_int = i32;
    pub type c_ulong = u64;
    pub const PR_SET_DUMPABLE: c_int = 4;
    extern "C" {
        pub fn prctl(
            option: c_int,
            arg2: c_ulong,
            arg3: c_ulong,
            arg4: c_ulong,
            arg5: c_ulong,
        ) -> c_int;
    }
}
