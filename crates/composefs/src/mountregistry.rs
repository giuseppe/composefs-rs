//! Mount registry for tracking active erofs mounts at runtime.
//!
//! When the same composefs image is mounted again (even from a different
//! process), the existing erofs mount can be reused as the overlay lower
//! layer.  This avoids creating duplicate erofs mounts for the same image.
//!
//! Instead of persisting file handles to disk, mounts are discovered at
//! runtime by enumerating the mount namespace via `listmount(2)` /
//! `statmount(2)` and identifying composefs overlay mounts by their
//! source string (`composefs:{name}`).  The erofs lower layer fd is then
//! obtained via the `OVL_IOC_OPEN_LAYER` ioctl.
//!
//! The race-free protocol is:
//!
//! 1. `listmount` -- enumerate mount IDs
//! 2. `statmount` -- check fs_type, source, options
//! 3. `open(mount_point, O_PATH)` -- grab a reference
//! 4. `statx(fd, STATX_MNT_ID_UNIQUE)` -- verify we opened the mount we inspected
//! 5. `ioctl(fd, OVL_IOC_OPEN_LAYER, idx)` -- retrieve erofs mount root fd
//! 6. `ioctl(erofs_fd, EROFS_IOC_GET_SOURCE_FD)` -- get the backing image file
//! 7. `FS_IOC_MEASURE_VERITY(source_fd)` -- verify verity digest matches

use std::collections::HashSet;
use std::os::fd::OwnedFd;
use std::path::Path;

use composefs_ioctls::mountid::{
    LSMT_ROOT, STATMOUNT_FS_TYPE, STATMOUNT_MNT_POINT, STATMOUNT_SB_SOURCE, erofs_get_source_fd,
    listmount, ovl_get_layers_info, ovl_open_layer, statmount, statx_mnt_id_unique,
};
use log::{debug, trace, warn};

use crate::fsverity::{FsVerityHashValue, measure_verity};

const COMPOSEFS_SOURCE_PREFIX: &str = "composefs:";

/// Try to reuse an existing erofs mount for the given composefs image.
///
/// Enumerates the mount namespace looking for an overlay mount whose source
/// is `composefs:{image_name}`.  The candidate's erofs backing file is
/// retrieved via `EROFS_IOC_GET_SOURCE_FD` and its fs-verity digest is
/// compared against `expected_verity`.  This ensures the reused mount is
/// backed by the exact same image content.
///
/// Returns an O_PATH fd to the erofs lower layer root, or `None` if no
/// suitable mount was found.
pub fn try_reuse<H: FsVerityHashValue>(image_name: &str, expected_verity: &H) -> Option<OwnedFd> {
    let expected_source = format!("{COMPOSEFS_SOURCE_PREFIX}{image_name}");

    debug!("try_reuse: looking for existing erofs mount for {image_name}");

    let ids = match listmount(LSMT_ROOT) {
        Ok(ids) => ids,
        Err(e) => {
            debug!("try_reuse: listmount failed: {e}");
            return None;
        }
    };

    debug!("try_reuse: scanning {} mounts", ids.len());

    let mask = STATMOUNT_FS_TYPE | STATMOUNT_SB_SOURCE | STATMOUNT_MNT_POINT;

    for mnt_id in ids {
        let sm = match statmount(mnt_id, mask) {
            Ok(sm) => sm,
            Err(e) => {
                trace!("try_reuse: statmount({mnt_id}) failed: {e}");
                continue;
            }
        };

        if sm.fs_type.as_deref() != Some("overlay") {
            continue;
        }

        trace!(
            "try_reuse: overlay mount {mnt_id}: source={:?}",
            sm.sb_source,
        );

        if sm.sb_source.as_deref() != Some(expected_source.as_str()) {
            continue;
        }

        let mount_point = match &sm.mnt_point {
            Some(p) => p.clone(),
            None => continue,
        };

        let mount_path = if mount_point.starts_with('/') {
            mount_point.clone()
        } else {
            format!("/{mount_point}")
        };

        let path_fd = match rustix::fs::open(
            mount_path.as_str(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                debug!("open({mount_path}, O_PATH) failed: {e}");
                continue;
            }
        };

        let actual_id = match statx_mnt_id_unique(&path_fd, Path::new("")) {
            Ok(id) => id,
            Err(e) => {
                debug!("statx_mnt_id_unique failed: {e}");
                continue;
            }
        };

        if actual_id != mnt_id {
            trace!("TOCTOU: mount at {mount_path} changed (expected {mnt_id}, got {actual_id})");
            continue;
        }

        let fd = match rustix::fs::open(
            mount_path.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                debug!("open({mount_path}, O_RDONLY) failed: {e}");
                continue;
            }
        };

        let layers_info = match ovl_get_layers_info(&fd) {
            Ok(info) => info,
            Err(e) => {
                debug!("OVL_IOC_GET_LAYERS_INFO failed for {image_name} at {mount_path}: {e}");
                continue;
            }
        };

        let total = 1 + layers_info.numlower as usize;

        for layer_idx in 1..total {
            let erofs_path_fd = match ovl_open_layer(&fd, layer_idx) {
                Ok(fd) => fd,
                Err(e) => {
                    warn!(
                        "OVL_IOC_OPEN_LAYER({layer_idx}) failed for {image_name} at {mount_path}: {e}"
                    );
                    break;
                }
            };

            let erofs_fd = match rustix::fs::open(
                crate::util::proc_self_fd(&erofs_path_fd),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    trace!("reopen lower layer {layer_idx} fd failed: {e}");
                    continue;
                }
            };

            let source_fd = match erofs_get_source_fd(&erofs_fd) {
                Ok(fd) => fd,
                Err(_) => continue,
            };

            let digest: H = match measure_verity(&source_fd) {
                Ok(d) => d,
                Err(e) => {
                    debug!("measure_verity on lower layer {layer_idx} source failed: {e}");
                    continue;
                }
            };

            if &digest != expected_verity {
                warn!(
                    "verity mismatch for {image_name} layer {layer_idx}: expected {}, got {}",
                    expected_verity.to_hex(),
                    digest.to_hex(),
                );
                continue;
            }

            debug!(
                "try_reuse: reusing erofs mount for {image_name} at {mount_path} layer {layer_idx} (verity verified)"
            );
            return Some(erofs_fd);
        }
    }

    debug!("try_reuse: no matching mount found for {image_name}");
    None
}

/// Return the set of image names that are currently backing active composefs mounts.
///
/// Enumerates the mount namespace and collects image names from overlay
/// mounts whose source matches `composefs:{name}`.
pub fn active_mounts() -> HashSet<String> {
    let ids = match listmount(LSMT_ROOT) {
        Ok(ids) => ids,
        Err(e) => {
            trace!("listmount failed: {e}");
            return HashSet::new();
        }
    };

    let mask = STATMOUNT_FS_TYPE | STATMOUNT_SB_SOURCE;

    let mut live = HashSet::new();

    for mnt_id in ids {
        let sm = match statmount(mnt_id, mask) {
            Ok(sm) => sm,
            Err(_) => continue,
        };

        if sm.fs_type.as_deref() != Some("overlay") {
            continue;
        }

        if let Some(source) = &sm.sb_source {
            if let Some(name) = source.strip_prefix(COMPOSEFS_SOURCE_PREFIX) {
                debug!("active composefs mount: {name}");
                live.insert(name.to_string());
            }
        }
    }

    live
}
