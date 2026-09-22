//! Open each directory relative to a verified descriptor. No symlink traversal,
//! user-writable parent, or FIFO is accepted for the root policy snapshot.
use crate::Snapshot;
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path},
};
fn owned_root(file: &File, directory: bool) -> Result<(), String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(
            "Policy and its parent directories must be root-owned and not group/world writable"
                .into(),
        );
    }
    Ok(())
}
pub fn read(path: &Path) -> Result<Snapshot, String> {
    read_json(path)
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    if !path.is_absolute() {
        return Err("Policy path must be absolute".into());
    }
    let mut directory = File::open("/").map_err(|e| e.to_string())?;
    owned_root(&directory, true)?;
    let mut components = path.components().peekable();
    components.next();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err("Invalid policy path".into());
        };
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
        let last = components.peek().is_none();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory owns a valid descriptor, name is NUL terminated.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        owned_root(&file, !last)?;
        if last {
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 1024 * 1024 {
                return Err("Policy exceeds 1 MiB".into());
            }
            return serde_json::from_slice(&bytes).map_err(|e| e.to_string());
        }
        directory = file;
    }
    Err("Missing policy filename".into())
}
