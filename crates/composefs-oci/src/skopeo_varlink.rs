//! Import container images via skopeo's JSON proxy + varlink socket.
//!
//! This module spawns a `skopeo experimental-image-proxy` subprocess,
//! opens a `containers-storage:` image through it, then calls
//! `OpenVarlinkSocket` to obtain a Unix socket speaking the
//! `org.composefs.Oci` varlink protocol.  Layers are transferred via
//! `GetLayer` over that socket, reusing the same `import_layer_via_transfer`
//! path as the in-process cstor import.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::{Context, Result};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::{ImportContext, Repository},
};

use crate::progress::{ComponentId, ProgressEvent, ProgressUnit, SharedReporter};
use crate::varlink_types::{GetLayerParams, OciProxy as _};
use crate::{ContentAndVerity, ImportStats, OciDigest, layer_identifier};


const MAX_MSG_SIZE: usize = 32 * 1024;

#[derive(serde::Serialize)]
struct Request {
    method: String,
    args: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct Reply {
    success: bool,
    error: String,
    #[allow(dead_code)]
    pipeid: u32,
    value: serde_json::Value,
}

/// Guard that keeps the skopeo child process alive.  Kills the child on drop.
pub(crate) struct SkopeoGuard {
    child: std::process::Child,
    _sock: OwnedFd,
}

impl Drop for SkopeoGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Send a JSON request over a `SOCK_SEQPACKET` socket and receive the reply,
/// optionally receiving a single file descriptor via `SCM_RIGHTS`.
fn proxy_call(
    sock: &OwnedFd,
    method: &str,
    args: Vec<serde_json::Value>,
) -> Result<(serde_json::Value, Option<OwnedFd>)> {
    let req = Request {
        method: method.to_string(),
        args,
    };
    let sendbuf = serde_json::to_vec(&req)?;
    rustix::net::send(sock, &sendbuf, rustix::net::SendFlags::empty())?;

    let mut buf = [0u8; MAX_MSG_SIZE];
    let mut cmsg_space: Vec<std::mem::MaybeUninit<u8>> =
        vec![std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg_buffer = rustix::net::RecvAncillaryBuffer::new(cmsg_space.as_mut_slice());
    let iov = std::io::IoSliceMut::new(&mut buf);
    let mut iov = [iov];
    let nread = rustix::net::recvmsg(
        sock,
        &mut iov,
        &mut cmsg_buffer,
        rustix::net::RecvFlags::CMSG_CLOEXEC,
    )?
    .bytes;

    let received_fd: Option<OwnedFd> = cmsg_buffer
        .drain()
        .filter_map(|m| match m {
            rustix::net::RecvAncillaryMessage::ScmRights(fds) => Some(fds),
            _ => None,
        })
        .flatten()
        .next();

    let reply: Reply = serde_json::from_slice(&buf[..nread])
        .with_context(|| format!("parsing reply for {method}"))?;
    if !reply.success {
        anyhow::bail!("skopeo proxy {method} failed: {}", reply.error);
    }

    Ok((reply.value, received_fd))
}

/// Spawn skopeo's image proxy, open the given image, and call
/// `OpenVarlinkSocket` to get a varlink connection.
///
/// Returns a `zlink::unix::Connection` and a guard that keeps skopeo alive.
pub(crate) fn open_skopeo_varlink(
    image_ref: &str,
) -> Result<(zlink::unix::Connection, SkopeoGuard)> {
    use std::process::{Command, Stdio};

    let (my_sock, their_sock) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;

    let mut cmd = Command::new("skopeo");
    cmd.arg("experimental-image-proxy");
    cmd.stdin(Stdio::from(their_sock));
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().context("failed to spawn skopeo")?;
    let sock: OwnedFd = my_sock;

    // Initialize — verify protocol version ≥ 0.2.9
    let (version_val, _) = proxy_call(&sock, "Initialize", vec![])?;
    let version_str: String = serde_json::from_value(version_val)?;
    let version = semver::Version::parse(&version_str)?;
    let required = semver::VersionReq::parse(">=0.2.9")?;
    anyhow::ensure!(
        required.matches(&version),
        "skopeo proxy version {version} too old, need >=0.2.9 for OpenVarlinkSocket"
    );

    // OpenImage
    let cs_ref = format!("containers-storage:{image_ref}");
    let (_img_val, _) = proxy_call(&sock, "OpenImage", vec![cs_ref.into()])?;

    // OpenVarlinkSocket — returns a socket fd via SCM_RIGHTS
    let (_, varlink_fd) = proxy_call(&sock, "OpenVarlinkSocket", vec![])?;
    let varlink_fd = varlink_fd.context("OpenVarlinkSocket did not return an fd")?;

    // Wrap as a zlink Connection
    let std_stream = UnixStream::from(varlink_fd);
    std_stream.set_nonblocking(true)?;
    let tokio_stream = tokio::net::UnixStream::from_std(std_stream)?;
    let zlink_stream =
        zlink::unix::Stream::try_from(tokio_stream).map_err(std::io::Error::other)?;
    let conn = zlink::Connection::new(zlink_stream);

    let guard = SkopeoGuard {
        child,
        _sock: sock,
    };

    Ok((conn, guard))
}

/// Full result of a skopeo varlink import: manifest and config digests + verities.
type SkopeoImportResult<ObjectID> = (ContentAndVerity<ObjectID>, ContentAndVerity<ObjectID>);

/// Import a container image from containers-storage via skopeo's varlink socket.
///
/// This spawns a `skopeo experimental-image-proxy`, opens the image, obtains a
/// varlink socket via `OpenVarlinkSocket`, then transfers each layer via
/// `GetLayer` and finalizes the OCI image in the repository.
pub(crate) async fn import_via_skopeo_proxy<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    image_ref: &str,
    reference: Option<&str>,
    zerocopy: bool,
    reporter: SharedReporter,
) -> Result<(SkopeoImportResult<ObjectID>, ImportStats)> {
    let mut stats = ImportStats::default();
    let mut ctx = ImportContext::default();

    // Spawn skopeo and get the varlink connection (blocking I/O)
    let image_ref_owned = image_ref.to_owned();
    let (mut conn, _guard) = tokio::task::spawn_blocking(move || {
        open_skopeo_varlink(&image_ref_owned)
    })
    .await
    .context("spawn_blocking(open_skopeo_varlink) failed")??;

    // GetImage returns manifest, config, and storage layer IDs.
    let image_reply = conn
        .get_image(image_ref)
        .await
        .context("Oci.GetImage RPC failed")?
        .map_err(|e| anyhow::anyhow!("Oci.GetImage error: {e:?}"))?;

    // Extract OCI diff-ids from the config JSON (the layer_digests from
    // GetImage are containers-storage layer IDs, not OCI diff-ids).
    let diff_ids = crate::extract_layer_ids(&image_reply.manifest, &image_reply.config)
        .context("extracting layer IDs from config")?;
    let diff_ids: Vec<OciDigest> = diff_ids
        .iter()
        .map(|s| s.parse::<OciDigest>().context("parsing diff_id"))
        .collect::<Result<_>>()?;

    let storage_layer_ids = &image_reply.layer_digests;
    anyhow::ensure!(
        diff_ids.len() == storage_layer_ids.len(),
        "layer count mismatch: {} diff_ids in config, {} storage layer IDs from GetImage",
        diff_ids.len(),
        storage_layer_ids.len()
    );

    stats.layers = diff_ids.len() as u64;

    // Import each layer via the varlink connection.
    // Use the storage layer ID for GetLayer (what the Go side expects)
    // but index by OCI diff-id in the composefs repo.
    let mut layer_refs = Vec::with_capacity(diff_ids.len());
    for (diff_id, storage_layer_id) in diff_ids.iter().zip(storage_layer_ids.iter()) {
        let content_id = layer_identifier(diff_id);
        let id = ComponentId::from(diff_id.to_string());

        let layer_verity = if let Some(existing) = repo.has_stream(&content_id)? {
            reporter.report(ProgressEvent::Skipped { id });
            stats.layers_already_present += 1;
            existing
        } else {
            reporter.report(ProgressEvent::Started {
                id: id.clone(),
                total: None,
                unit: ProgressUnit::Bytes,
            });
            let params = GetLayerParams {
                diff_id: Some(storage_layer_id.clone()),
                storage: None,
            };
            let (verity, layer_stats) =
                crate::cstor::import_layer_via_transfer(
                    repo,
                    &mut conn,
                    params,
                    diff_id,
                    zerocopy,
                    &mut ctx,
                )
                .await?;
            let bytes = layer_stats.new_bytes();
            stats.merge(&layer_stats);
            reporter.report(ProgressEvent::Done {
                id,
                transferred: bytes,
            });
            verity
        };

        layer_refs.push((diff_id.clone(), layer_verity));
    }

    reporter.report(ProgressEvent::Message("Layers imported".to_string()));

    // Finalize the OCI image
    let repo2 = Arc::clone(repo);
    let manifest_json = image_reply.manifest.into_bytes();
    let config_json = image_reply.config.into_bytes();
    let reference_owned = reference.map(|s| s.to_owned());
    let reporter2 = reporter.clone();

    let (result, final_stats) = tokio::task::spawn_blocking(move || {
        reporter2.report(ProgressEvent::Message("Finalizing image".to_string()));
        let result = crate::layer_sync::finalize_oci_image(
            &repo2,
            &manifest_json,
            &config_json,
            &layer_refs,
            reference_owned.as_deref(),
        )
        .context("finalize_oci_image")?;
        Ok::<_, anyhow::Error>((result, stats))
    })
    .await
    .context("spawn_blocking(finalize_oci_image) failed")??;

    Ok((result, final_stats))
}
