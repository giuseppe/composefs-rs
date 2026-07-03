//! Wrappers for mount-ID-related syscalls not yet exposed by rustix.
#![allow(unsafe_code)]

use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::path::Path;

const ENOENT: i32 = libc::ENOENT;
const ENOSYS: i32 = libc::ENOSYS;

// statmount(2) was added in 6.8, after the generic syscall table
// unification, so 457 is correct for all non-MIPS architectures.
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6"
)))]
const SYS_STATMOUNT: libc::c_long = 457;
#[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
const SYS_STATMOUNT: libc::c_long = 4457;
#[cfg(any(target_arch = "mips64", target_arch = "mips64r6"))]
const SYS_STATMOUNT: libc::c_long = 5457;

const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
const AT_EMPTY_PATH: i32 = libc::AT_EMPTY_PATH;
const AT_HANDLE_MNT_ID_UNIQUE: i32 = 0x001;
const MAX_HANDLE_SZ: usize = 128;

#[repr(C)]
struct MntIdReq {
    size: u32,
    spare: u32,
    mnt_id: u64,
    param: u64,
    mnt_ns_id: u64,
}

#[repr(C)]
struct Statmount {
    size: u32,
    _pad: [u8; 252],
}

/// Check whether a mount with the given unique ID is still active.
///
/// Returns `Ok(true)` if the mount exists, `Ok(false)` if it has been
/// unmounted (`ENOENT`), or `Err` with `ENOSYS` on kernels that do
/// not support `statmount(2)` (< 6.8).
pub fn statmount_exists(mnt_id: u64) -> std::io::Result<bool> {
    let req = MntIdReq {
        size: std::mem::size_of::<MntIdReq>() as u32,
        spare: 0,
        mnt_id,
        param: 0,
        mnt_ns_id: 0,
    };
    let mut buf = Statmount {
        size: 0,
        _pad: [0u8; 252],
    };
    let ret = unsafe {
        libc::syscall(
            SYS_STATMOUNT,
            &req as *const MntIdReq,
            &mut buf as *mut Statmount,
            std::mem::size_of::<Statmount>(),
            0u32,
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(ENOENT) {
        return Ok(false);
    }
    Err(err)
}

/// Get the unique (non-recycling) mount ID for the filesystem at `path`.
///
/// Uses `statx` with `STATX_MNT_ID_UNIQUE` (kernel 6.8+). Returns the
/// 64-bit unique mount ID, or an error if the kernel does not support it.
pub fn statx_mnt_id_unique(dirfd: impl AsFd, path: &Path) -> std::io::Result<u64> {
    use rustix::fs::{AtFlags, StatxFlags};

    let at_flags = if path.as_os_str().is_empty() {
        AtFlags::EMPTY_PATH
    } else {
        AtFlags::empty()
    };
    let flags = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
    let st = rustix::fs::statx(dirfd, path, at_flags, flags)
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;

    if st.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
        return Err(std::io::Error::from_raw_os_error(ENOSYS));
    }

    Ok(st.stx_mnt_id)
}

#[repr(C)]
struct RawFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; MAX_HANDLE_SZ],
}

/// A file handle obtained from `name_to_handle_at`.
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// Size of the handle data in bytes.
    pub handle_bytes: u32,
    /// Filesystem-specific handle type.
    pub handle_type: i32,
    /// Opaque handle data.
    pub f_handle: Vec<u8>,
}

/// Result of `name_to_handle_at` with `AT_HANDLE_MNT_ID_UNIQUE`.
#[derive(Debug)]
pub struct MountHandle {
    /// The file handle for the root of the mount.
    pub handle: FileHandle,
    /// The 64-bit unique mount ID (never recycled within a boot).
    pub mount_id: u64,
}

/// Get a file handle and unique mount ID for the root of the given mount.
///
/// Calls `name_to_handle_at(fd, "", AT_EMPTY_PATH | AT_HANDLE_MNT_ID_UNIQUE)`.
/// The returned [`MountHandle`] contains the file handle (usable with
/// [`open_by_handle_at`]) and the 64-bit unique mount ID.
pub fn name_to_handle_at_root(dirfd: impl AsFd) -> std::io::Result<MountHandle> {
    use std::os::fd::AsRawFd;

    let mut handle = RawFileHandle {
        handle_bytes: MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0u8; MAX_HANDLE_SZ],
    };
    let mut mount_id: u64 = 0;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            dirfd.as_fd().as_raw_fd(),
            c"".as_ptr(),
            &mut handle as *mut RawFileHandle,
            &mut mount_id as *mut u64,
            AT_EMPTY_PATH | AT_HANDLE_MNT_ID_UNIQUE,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let bytes = handle.handle_bytes as usize;
    Ok(MountHandle {
        handle: FileHandle {
            handle_bytes: handle.handle_bytes,
            handle_type: handle.handle_type,
            f_handle: handle.f_handle[..bytes].to_vec(),
        },
        mount_id,
    })
}

/// Open a file by its handle, returning a read-only directory fd.
///
/// Calls `open_by_handle_at(mountdirfd, handle, O_RDONLY | O_DIRECTORY | O_CLOEXEC)`.
/// The `mountdirfd` must be an fd on the same mount that produced the handle.
pub fn open_by_handle_at(mountdirfd: impl AsFd, handle: &FileHandle) -> std::io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;

    let mut raw = RawFileHandle {
        handle_bytes: handle.handle_bytes,
        handle_type: handle.handle_type,
        f_handle: [0u8; MAX_HANDLE_SZ],
    };
    let len = handle.handle_bytes as usize;
    raw.f_handle[..len].copy_from_slice(&handle.f_handle[..len]);

    let ret = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mountdirfd.as_fd().as_raw_fd(),
            &raw as *const RawFileHandle,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Open a file by its handle using a unique mount ID instead of a mount fd.
///
/// Passes `AT_HANDLE_MNT_ID_UNIQUE` so the kernel looks up the mount by
/// its 64-bit unique ID (the first argument) rather than requiring an fd
/// on the same mount.  Requires kernel 6.12+.
pub fn open_by_handle_at_mnt_id(mount_id: u64, handle: &FileHandle) -> std::io::Result<OwnedFd> {
    let mut raw = RawFileHandle {
        handle_bytes: handle.handle_bytes,
        handle_type: handle.handle_type,
        f_handle: [0u8; MAX_HANDLE_SZ],
    };
    let len = handle.handle_bytes as usize;
    raw.f_handle[..len].copy_from_slice(&handle.f_handle[..len]);

    let ret = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mount_id as libc::c_long,
            &raw as *const RawFileHandle,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | AT_HANDLE_MNT_ID_UNIQUE,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}
