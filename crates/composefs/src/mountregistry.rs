//! Mount registry for tracking active erofs mounts at runtime.
//!
//! The mount registry serves two purposes:
//!
//! 1. **Mount reuse** — When the same image is mounted again (even
//!    from a different process), the existing erofs mount is reused as
//!    the overlay lower layer.  The erofs mount's file handle and
//!    unique mount ID are persisted to disk; on reuse,
//!    `open_by_handle_at` with the stored mount ID reopens the root.
//!
//! 2. **GC protection** — GC reads these entries and calls `statmount`
//!    to check whether each erofs mount is still alive, treating live
//!    mounts as GC roots.
//!
//! Registry files are stored at `<rundir>/mounts/<image>.<kind>`,
//! each containing the unique mount ID and file handle in text form.
//!
//! The erofs mounts themselves are kept attached under
//! `<rundir>/erofs/<image>.<kind>/` so they remain visible in the
//! mount namespace for `open_by_handle_at` lookups.
//!
//! The runtime directory is `$XDG_RUNTIME_DIR/composefs` when set
//! (for unprivileged users) or `/run/composefs` otherwise.
//!
//! Mount IDs are 64-bit, never recycled within a boot.  The runtime
//! directory lives on a tmpfs cleared on reboot, so stale entries
//! cannot accumulate across boots.

use std::collections::HashSet;
use std::fmt;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use composefs_ioctls::mountid::{
    FileHandle, name_to_handle_at_root, open_by_handle_at_mnt_id, statmount_exists,
};
use log::{debug, trace, warn};
use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::mount::{MoveMountFlags, UnmountFlags, move_mount, unmount};

fn composefs_run_dir() -> PathBuf {
    if rustix::process::getuid().is_root() {
        PathBuf::from("/run/composefs")
    } else {
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(dir) => PathBuf::from(dir).join("composefs"),
            None => PathBuf::from("/run/composefs"),
        }
    }
}

/// The kind of mount used to attach an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountKind {
    /// Kernel composefs/erofs mount
    Native,
    /// FUSE-based mount
    Fuse,
}

impl fmt::Display for MountKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountKind::Native => f.write_str("native"),
            MountKind::Fuse => f.write_str("fuse"),
        }
    }
}

fn entry_filename(image_name: &str, kind: MountKind) -> String {
    format!("{}.{kind}", image_name.replace('/', "_"))
}

fn image_name_from_entry(filename: &str) -> Option<String> {
    let stem = filename.rsplit_once('.')?.0;
    Some(stem.replace('_', "/"))
}

fn serialize_mount_entry(mount_id: u64, handle: &FileHandle) -> String {
    let hex: String = handle.f_handle.iter().map(|b| format!("{b:02x}")).collect();
    format!("{mount_id} {} {hex}", handle.handle_type)
}

fn deserialize_mount_entry(data: &str) -> Option<(u64, FileHandle)> {
    let mut parts = data.trim().split_whitespace();
    let mount_id: u64 = parts.next()?.parse().ok()?;
    let handle_type: i32 = parts.next()?.parse().ok()?;
    let hex = parts.next()?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let f_handle: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    Some((
        mount_id,
        FileHandle {
            handle_bytes: f_handle.len() as u32,
            handle_type,
            f_handle,
        },
    ))
}

/// Disk-backed registry of erofs mounts for reuse and GC protection.
///
/// On registration the erofs fsmount is attached to a persistent path
/// under `<rundir>/erofs/` and its file handle and unique mount ID
/// are stored under `<rundir>/mounts/`.  On reuse,
/// `open_by_handle_at` with the stored mount ID reopens the erofs
/// root — the caller only needs the mount ID and handle, not an fd.
#[derive(Debug)]
pub struct MountRegistry {
    mounts_dir: PathBuf,
    erofs_dir: PathBuf,
}

impl MountRegistry {
    /// Create a mount registry backed by the default runtime directory.
    pub fn new() -> Self {
        let base = composefs_run_dir();
        MountRegistry {
            mounts_dir: base.join("mounts"),
            erofs_dir: base.join("erofs"),
        }
    }

    /// Try to reuse a cached erofs mount for the given image.
    ///
    /// Reads the stored mount ID and file handle from disk, then
    /// reopens the erofs root via `open_by_handle_at` with the mount
    /// ID.  Returns `None` if no entry exists or the mount is gone.
    pub fn try_reuse(&self, image_name: &str, kind: MountKind) -> Option<OwnedFd> {
        let filename = entry_filename(image_name, kind);
        let reg_path = self.mounts_dir.join(&filename);

        let data = match std::fs::read_to_string(&reg_path) {
            Ok(d) => d,
            Err(_) => return None,
        };

        let (mount_id, handle) = match deserialize_mount_entry(&data) {
            Some(v) => v,
            None => {
                warn!("invalid mount entry in {}", reg_path.display());
                let _ = std::fs::remove_file(&reg_path);
                return None;
            }
        };

        match open_by_handle_at_mnt_id(mount_id, &handle) {
            Ok(fd) => {
                debug!("reusing erofs mount for {image_name} (mnt_id={mount_id})");
                Some(fd)
            }
            Err(e) => {
                debug!("erofs mount gone for {image_name} (mnt_id={mount_id}): {e}");
                let _ = std::fs::remove_file(&reg_path);
                let mount_dir = self.erofs_dir.join(&filename);
                let _ = unmount(&mount_dir, UnmountFlags::DETACH);
                let _ = std::fs::remove_dir(&mount_dir);
                None
            }
        }
    }

    /// Attach an erofs mount and register it for reuse and GC protection.
    ///
    /// Moves the detached erofs fsmount to a persistent path under the
    /// runtime directory so it stays visible in the mount namespace.
    /// Then obtains a file handle and unique mount ID via
    /// `name_to_handle_at` and stores both on disk.
    ///
    /// Returns an fd on the erofs root for use as the overlay lower
    /// layer.
    pub fn register(
        &self,
        image_name: &str,
        kind: MountKind,
        erofs_mnt: OwnedFd,
    ) -> Result<OwnedFd> {
        let filename = entry_filename(image_name, kind);

        let mount_dir = self.erofs_dir.join(&filename);
        std::fs::create_dir_all(&mount_dir)
            .with_context(|| format!("creating {}", mount_dir.display()))?;

        // Clear any stale mount left from a previous run
        let _ = unmount(&mount_dir, UnmountFlags::DETACH);

        move_mount(
            erofs_mnt.as_fd(),
            "",
            CWD,
            &mount_dir,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .context("attaching erofs to persistent mountpoint")?;

        let erofs_fd = openat(
            CWD,
            &mount_dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("opening persistent erofs mountpoint")?;

        let root_fd = openat(
            erofs_fd.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("opening erofs mount root")?;

        let mnt_handle =
            name_to_handle_at_root(&root_fd).context("name_to_handle_at on erofs root")?;

        let mount_id = mnt_handle.mount_id;
        let data = serialize_mount_entry(mount_id, &mnt_handle.handle);

        std::fs::create_dir_all(&self.mounts_dir)
            .with_context(|| format!("creating {}", self.mounts_dir.display()))?;

        let reg_path = self.mounts_dir.join(&filename);
        let mut f = std::fs::File::create(&reg_path)
            .with_context(|| format!("creating {}", reg_path.display()))?;
        write!(f, "{data}")?;

        debug!("registered {kind} erofs mount for {image_name}: mnt_id={mount_id}");
        Ok(erofs_fd)
    }
}

impl Default for MountRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the set of image names that are currently backing active erofs mounts.
///
/// Reads the mount registry, validates each entry with `statmount`,
/// and removes stale entries.  Returns the set of image names whose
/// erofs mounts are still alive.
///
/// Returns an empty set if the registry does not exist or cannot be
/// read (e.g., `/run` not available, kernel too old).
pub fn active_mounts() -> HashSet<String> {
    match read_mount_entries(&composefs_run_dir().join("mounts")) {
        Ok(set) => set,
        Err(e) => {
            trace!("mount registry unavailable: {e:#}");
            HashSet::new()
        }
    }
}

fn read_mount_entries(dir: &Path) -> Result<HashSet<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(e).context("reading mount registry"),
    };

    let mut live = HashSet::new();

    for entry in entries {
        let entry = entry.context("reading mount registry entry")?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };

        let path = entry.path();
        let data = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("cannot read mount entry {}: {e}", path.display());
                continue;
            }
        };

        let (mount_id, _handle) = match deserialize_mount_entry(&data) {
            Some(v) => v,
            None => {
                warn!("invalid mount entry in {}", path.display());
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        match statmount_exists(mount_id) {
            Ok(true) => {
                if let Some(image_name) = image_name_from_entry(name_str) {
                    debug!("erofs mount alive: {name_str} (mnt_id={mount_id})");
                    live.insert(image_name);
                }
            }
            Ok(false) => {
                debug!("erofs mount gone: {name_str} (mnt_id={mount_id}), removing entry");
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => {
                if e.raw_os_error() == Some(rustix::io::Errno::NOSYS.raw_os_error()) {
                    return Ok(HashSet::new());
                }
                warn!("statmount({mount_id}) failed: {e}");
            }
        }
    }

    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_roundtrip() {
        let handle = FileHandle {
            handle_bytes: 4,
            handle_type: 1,
            f_handle: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let data = serialize_mount_entry(12345, &handle);
        let (mount_id, h) = deserialize_mount_entry(&data).unwrap();
        assert_eq!(mount_id, 12345);
        assert_eq!(h.handle_bytes, 4);
        assert_eq!(h.handle_type, 1);
        assert_eq!(h.f_handle, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_deserialize_invalid() {
        assert!(deserialize_mount_entry("").is_none());
        assert!(deserialize_mount_entry("not a number").is_none());
        assert!(deserialize_mount_entry("123 1 zz").is_none());
        assert!(deserialize_mount_entry("123 1 abc").is_none());
    }

    #[test]
    fn test_entry_filename() {
        assert_eq!(entry_filename("abcdef", MountKind::Native), "abcdef.native");
        assert_eq!(
            entry_filename("refs/myimage", MountKind::Fuse),
            "refs_myimage.fuse"
        );
    }

    #[test]
    fn test_image_name_from_entry() {
        assert_eq!(
            image_name_from_entry("abcdef.native"),
            Some("abcdef".to_string())
        );
        assert_eq!(
            image_name_from_entry("refs_myimage.fuse"),
            Some("refs/myimage".to_string())
        );
        assert_eq!(image_name_from_entry("noextension"), None);
    }

    #[test]
    fn test_registry_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nonexistent");
        let live = read_mount_entries(&dir).unwrap();
        assert!(live.is_empty());
    }

    #[test]
    fn test_registry_stale_entry_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mounts");
        std::fs::create_dir_all(&dir).unwrap();

        let bogus_id: u64 = u64::MAX - 42;
        match statmount_exists(bogus_id) {
            Ok(false) => {}
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOSYS.raw_os_error()) => {
                eprintln!("skipping: statmount not supported (ENOSYS)");
                return;
            }
            other => panic!("expected Ok(false) for bogus mount ID, got {other:?}"),
        }

        let handle = FileHandle {
            handle_bytes: 4,
            handle_type: 1,
            f_handle: vec![0x01, 0x02, 0x03, 0x04],
        };
        let data = serialize_mount_entry(bogus_id, &handle);
        let path = dir.join("test-image.native");
        std::fs::write(&path, &data).unwrap();

        assert!(path.exists());
        let live = read_mount_entries(&dir).unwrap();
        assert!(live.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn test_mount_registry_try_reuse_nonexistent() {
        let registry = MountRegistry {
            mounts_dir: PathBuf::from("/nonexistent/path"),
            erofs_dir: PathBuf::from("/nonexistent/erofs"),
        };
        assert!(registry.try_reuse("test", MountKind::Native).is_none());
    }
}
