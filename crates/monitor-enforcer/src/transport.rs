//! Read-only, root-to-root local IPC. No process inventory or activity history is
//! persisted. Policy mutation is intentionally not exposed on this socket.
use crate::{FileAuthorizer, RuntimeSnapshot};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
pub const RUNTIME_SOCKET: &str = "/Library/Application Support/Monitor/Enforcement/runtime.sock";
fn root_directory(path: &Path) -> Result<File, String> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    if !path.is_absolute() {
        return Err("Absolute directory required".into());
    }
    let mut directory = File::open("/").map_err(|e| e.to_string())?;
    for part in path.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err("Invalid directory".into());
        };
        let name = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("Untrusted runtime directory".into());
        }
    }
    Ok(directory)
}
fn root_peer(stream: &UnixStream) -> bool {
    let mut uid = 0;
    let mut gid = 0;
    unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == 0 }
}
pub fn bind(path: &Path) -> Result<UnixListener, String> {
    let _directory = root_directory(path.parent().ok_or("Missing socket parent")?)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.uid() != 0 || !metadata.file_type().is_socket() {
            return Err("Untrusted runtime socket".into());
        }
        if UnixStream::connect(path).is_ok() {
            return Err("Runtime publisher is already running".into());
        }
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(listener)
}
pub fn serve(
    listener: UnixListener,
    authorizer: Arc<Mutex<FileAuthorizer>>,
    active: Arc<AtomicBool>,
    path: std::path::PathBuf,
) {
    while active.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if !root_peer(&stream) {
                    continue;
                }
                let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                let snapshot = authorizer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .runtime_snapshot();
                if let Ok(bytes) = serde_json::to_vec(&snapshot) {
                    if bytes.len() <= 1024 * 1024 {
                        let _ = stream.write_all(&bytes);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(_) => break,
        }
    }
    let _ = std::fs::remove_file(path);
}
pub fn read() -> Result<RuntimeSnapshot, String> {
    let path = Path::new(RUNTIME_SOCKET);
    let _directory = root_directory(path.parent().unwrap())?;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || !metadata.file_type().is_socket() {
        return Err("Untrusted runtime socket".into());
    }
    let stream = UnixStream::connect(path).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    if !root_peer(&stream) {
        return Err("Runtime peer is not root".into());
    }
    let mut bytes = Vec::new();
    stream
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("Runtime response too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
