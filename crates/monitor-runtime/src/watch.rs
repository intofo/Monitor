//! Native file notifications, coalesced to at most one bounded scan per second.
use crate::scan::{self, ScanReport, Source};
use notify::{EventKind, RecursiveMode, Watcher};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, RecvTimeoutError},
        Arc,
    },
    time::{Duration, Instant},
};

pub fn watch(
    sources: &[Source],
    mut emit: impl FnMut(ScanReport) -> Result<(), String>,
) -> Result<(), String> {
    let (tx, rx) = sync_channel(1);
    let backend_error = Arc::new(AtomicBool::new(false));
    let error_flag = backend_error.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        let changed = match event {
            Ok(e) => !matches!(e.kind, EventKind::Access(_)),
            Err(_) => {
                error_flag.store(true, Ordering::Relaxed);
                true
            }
        };
        if changed {
            let _ = tx.try_send(());
        } // Full queue coalesces; next scan reads current evidence.
    })
    .map_err(|e| format!("无法启动文件通知: {e}"))?;
    watcher
        .configure(notify::Config::default().with_follow_symlinks(false))
        .map_err(|e| e.to_string())?;
    let mut watched = 0;
    for source in sources {
        if std::fs::symlink_metadata(&source.root)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
        {
            watcher
                .watch(&source.root, RecursiveMode::Recursive)
                .map_err(|e| format!("无法监测证据目录: {e}"))?;
            watched += 1;
        }
    }
    emit(scan::scan(sources))?;
    if watched == 0 {
        return Err("没有现存证据目录；目录创建后重新启动 watch".into());
    }
    loop {
        rx.recv().map_err(|_| "文件通知已中断")?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(remaining) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Err("文件通知已中断".into()),
            }
        }
        if backend_error.swap(false, Ordering::Relaxed) {
            return Err("文件通知后端报告错误，监测覆盖不能保证；请重新扫描并重启".into());
        }
        emit(scan::scan(sources))?;
    }
}
