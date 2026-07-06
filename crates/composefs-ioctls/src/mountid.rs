//! Wrappers for mount-ID-related syscalls: statx, listmount, statmount,
//! and the overlay layer ioctls (`OVL_IOC_OPEN_LAYER`, `OVL_IOC_GET_LAYERS_INFO`).
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6"
)))]
const SYS_STATMOUNT: std::ffi::c_long = 457;
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6"
)))]
const SYS_LISTMOUNT: std::ffi::c_long = 458;

#[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
const SYS_STATMOUNT: std::ffi::c_long = 4457;
#[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
const SYS_LISTMOUNT: std::ffi::c_long = 4458;

#[cfg(any(target_arch = "mips64", target_arch = "mips64r6"))]
const SYS_STATMOUNT: std::ffi::c_long = 5457;
#[cfg(any(target_arch = "mips64", target_arch = "mips64r6"))]
const SYS_LISTMOUNT: std::ffi::c_long = 5458;

/// Request filesystem type string from `statmount(2)`.
pub const STATMOUNT_FS_TYPE: u64 = 0x00000020;
/// Request mount point path from `statmount(2)`.
pub const STATMOUNT_MNT_POINT: u64 = 0x00000010;
/// Request superblock source string from `statmount(2)`.
pub const STATMOUNT_SB_SOURCE: u64 = 0x00000200;
/// Request filesystem options array from `statmount(2)`.
pub const STATMOUNT_OPT_ARRAY: u64 = 0x00000400;

/// Sentinel mount ID for `listmount(2)`: enumerate from the root.
pub const LSMT_ROOT: u64 = 0xffffffffffffffff;

const MNT_ID_REQ_SIZE_VER0: u32 = 24;

#[repr(C)]
struct MntIdReq {
    size: u32,
    spare: u32,
    mnt_id: u64,
    param: u64,
}

#[repr(C)]
struct RawStatmount {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    mnt_ns_id: u64,
    fs_subtype: u32,
    sb_source: u32,
    opt_num: u32,
    opt_array: u32,
    opt_sec_num: u32,
    opt_sec_array: u32,
    supported_mask: u64,
    mnt_uidmap_num: u32,
    mnt_uidmap: u32,
    mnt_gidmap_num: u32,
    mnt_gidmap: u32,
    spare2: [u64; 43],
}

unsafe extern "C" {
    fn syscall(num: std::ffi::c_long, ...) -> std::ffi::c_long;
}

/// Parsed result from a `statmount(2)` call.
#[derive(Debug, Default)]
pub struct StatmountResult {
    /// Unique mount ID.
    pub mnt_id: u64,
    /// Filesystem type (e.g. "overlay", "erofs").
    pub fs_type: Option<String>,
    /// Superblock source string (e.g. "composefs:myimage").
    pub sb_source: Option<String>,
    /// Mount point path relative to the filesystem root.
    pub mnt_point: Option<String>,
    /// Filesystem-specific options as individual strings.
    pub opt_array: Option<Vec<String>>,
}

/// Get the unique (non-recycling) mount ID for the filesystem at `path`.
///
/// Uses `statx` with `STATX_MNT_ID_UNIQUE` (kernel 6.8+).
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
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }

    Ok(st.stx_mnt_id)
}

/// Enumerate mount IDs in the current mount namespace.
///
/// Returns all mount IDs visible from `parent_mnt_id`. Pass [`LSMT_ROOT`]
/// to list all mounts.
pub fn listmount(parent_mnt_id: u64) -> std::io::Result<Vec<u64>> {
    let mut all = Vec::new();
    let mut last_mnt_id: u64 = 0;

    loop {
        let mut buf = [0u64; 512];
        let req = MntIdReq {
            size: MNT_ID_REQ_SIZE_VER0,
            spare: 0,
            mnt_id: parent_mnt_id,
            param: last_mnt_id,
        };

        let ret = unsafe {
            syscall(
                SYS_LISTMOUNT,
                &req as *const MntIdReq,
                buf.as_mut_ptr(),
                buf.len(),
                0u32,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let count = ret as usize;
        if count == 0 {
            break;
        }

        all.extend_from_slice(&buf[..count]);
        last_mnt_id = buf[count - 1];

        if count < buf.len() {
            break;
        }
    }

    Ok(all)
}

/// Query metadata about a mount by its unique mount ID.
pub fn statmount(mnt_id: u64, mask: u64) -> std::io::Result<StatmountResult> {
    let req = MntIdReq {
        size: MNT_ID_REQ_SIZE_VER0,
        spare: 0,
        mnt_id,
        param: mask,
    };

    let buf_size = 4096usize;
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    let ret = unsafe {
        syscall(
            SYS_STATMOUNT,
            &req as *const MntIdReq,
            buf.as_mut_ptr(),
            buf_size,
            0u32,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EOVERFLOW) {
            let buf_size = 64 * 1024;
            buf.resize(buf_size, 0);
            let ret = unsafe {
                syscall(
                    SYS_STATMOUNT,
                    &req as *const MntIdReq,
                    buf.as_mut_ptr(),
                    buf_size,
                    0u32,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        } else {
            return Err(err);
        }
    }

    let raw = unsafe { &*(buf.as_ptr() as *const RawStatmount) };

    let mut result = StatmountResult {
        mnt_id: raw.mnt_id,
        ..Default::default()
    };

    let got = raw.mask;
    let str_base = std::mem::size_of::<RawStatmount>() as u32;

    if got & STATMOUNT_FS_TYPE != 0 {
        result.fs_type = extract_string(&buf, str_base + raw.fs_type);
    }
    if got & STATMOUNT_SB_SOURCE != 0 {
        result.sb_source = extract_string(&buf, str_base + raw.sb_source);
    }
    if got & STATMOUNT_MNT_POINT != 0 {
        result.mnt_point = extract_string(&buf, str_base + raw.mnt_point);
    }
    if got & STATMOUNT_OPT_ARRAY != 0 {
        result.opt_array = Some(extract_string_array(
            &buf,
            str_base + raw.opt_array,
            raw.opt_num,
        ));
    }

    Ok(result)
}

fn extract_string(buf: &[u8], offset: u32) -> Option<String> {
    let offset = offset as usize;
    if offset == 0 || offset >= buf.len() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf[offset..].as_ptr() as *const _) };
    Some(cstr.to_string_lossy().into_owned())
}

fn extract_string_array(buf: &[u8], offset: u32, count: u32) -> Vec<String> {
    let mut result = Vec::with_capacity(count as usize);
    let mut pos = offset as usize;

    for _ in 0..count {
        if pos >= buf.len() {
            break;
        }
        let cstr = unsafe { CStr::from_ptr(buf[pos..].as_ptr() as *const _) };
        let s = cstr.to_string_lossy().into_owned();
        pos += cstr.to_bytes_with_nul().len();
        result.push(s);
    }

    result
}

/// Open an overlay layer fd via `OVL_IOC_OPEN_LAYER`.
///
/// `fd` must be an fd to any file or directory on the overlay.
/// `index` is the layer index: 0 for the upper layer, >= 1 for lower layers.
pub fn ovl_open_layer(fd: impl AsFd, index: usize) -> std::io::Result<OwnedFd> {
    const OVL_IOC_OPEN_LAYER: libc::c_ulong = 0x4f01;

    let ret = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), OVL_IOC_OPEN_LAYER, index) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret) })
}

/// Overlay layer configuration summary.
#[repr(C)]
#[derive(Debug, Default)]
pub struct OvlLayersInfo {
    /// Number of lower (metadata) layers.
    pub numlower: u32,
    /// Number of data-only lower layers.
    pub numlowerdata: u32,
    /// 1 if an upper layer is configured, 0 otherwise.
    pub has_upper: u32,
}

/// Retrieve overlay layer configuration via `OVL_IOC_GET_LAYERS_INFO`.
pub fn ovl_get_layers_info(fd: impl AsFd) -> std::io::Result<OvlLayersInfo> {
    const OVL_IOC_GET_LAYERS_INFO: libc::c_ulong = 0x800c4f02;

    let mut info = OvlLayersInfo::default();
    let ret = unsafe {
        libc::ioctl(
            fd.as_fd().as_raw_fd(),
            OVL_IOC_GET_LAYERS_INFO,
            &mut info as *mut OvlLayersInfo,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(info)
}

/// Retrieve the backing source file fd from a file-backed erofs mount.
///
/// Returns an fd to the image file that backs the erofs filesystem.
/// This fd can be used with `FS_IOC_MEASURE_VERITY` to verify the
/// identity of the mounted image.
///
/// Returns `ENOENT` for block-device-backed erofs mounts.
pub fn erofs_get_source_fd(fd: impl AsFd) -> std::io::Result<OwnedFd> {
    const EROFS_IOC_GET_SOURCE_FD: libc::c_ulong = 0x6501;

    let ret = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), EROFS_IOC_GET_SOURCE_FD) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(ret) })
}
