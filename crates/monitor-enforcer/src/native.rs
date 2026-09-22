use crate::{FileAuthorizer, ProcessIdentity, ProcessKey, Scope};
use monitor_core::protection::Verdict;
use serde::Serialize;
use std::{
    ffi::c_void,
    io::Write,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{sync_channel, SyncSender},
        Arc, Mutex,
    },
};
#[repr(C)]
struct Text {
    data: *const u8,
    length: usize,
}
impl Text {
    fn value(&self) -> &str {
        if self.length == 0 || self.length > 4096 || self.data.is_null() {
            return "";
        }
        // SAFETY: native shim only passes ES strings for the synchronous callback;
        // buffers remain valid until this callback returns. Never retained here.
        std::str::from_utf8(unsafe { std::slice::from_raw_parts(self.data, self.length) })
            .unwrap_or("")
    }
}
#[repr(C)]
struct Process {
    pid: u32,
    version: u32,
    uid: u32,
    valid_signature: u32,
    executable: Text,
    signing_id: Text,
    team_id: Text,
    cdhash: [u8; 20],
}
impl Process {
    fn identity(&self) -> ProcessIdentity<'_> {
        ProcessIdentity {
            key: ProcessKey {
                pid: self.pid,
                version: self.version,
            },
            uid: self.uid,
            executable: self.executable.value(),
            signature_valid: self.valid_signature != 0,
            cdhash: self.cdhash,
        }
    }
}
#[repr(C)]
struct Event {
    kind: u32,
    readable: u32,
    truncated: u32,
    regular_file: u32,
    links: u64,
    sequence: u64,
    has_sequence: u32,
    process: Process,
    related: Process,
    path: Text,
    cwd: Text,
    cwd_truncated: u32,
}
#[derive(Serialize)]
struct Record {
    kind: &'static str,
    revision: u64,
    pid: u32,
    pid_version: u32,
    agent_id: String,
    target: String,
    operation: &'static str,
    enforced: bool,
    approval_required: bool,
    ai_review_required: bool,
    response_accepted: bool,
    sequence: Option<u64>,
}
struct Context {
    authorizer: Arc<Mutex<FileAuthorizer>>,
    sender: SyncSender<Record>,
    lost: Arc<AtomicU64>,
}
impl Context {
    fn emit(&self, record: Record) {
        if self.sender.try_send(record).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}
unsafe extern "C" {
    fn mon_preflight() -> u32;
    fn mon_event_size() -> usize;
    fn mon_run(
        context: *mut c_void,
        decide: extern "C" fn(*mut c_void, *const Event, *mut u32) -> u32,
        completed: extern "C" fn(*mut c_void, *const Event, u32, u32, u32),
    ) -> i32;
}
#[derive(Serialize)]
pub struct Preflight {
    pub endpoint_security_entitlement: bool,
    pub privileged: bool,
    pub enforcement_active: bool,
}
pub fn preflight() -> Preflight {
    // SAFETY: does not create an ES client or request system authorization.
    let flags = unsafe { mon_preflight() };
    Preflight {
        endpoint_security_entitlement: flags & 1 != 0,
        privileged: flags & 2 != 0,
        enforcement_active: false,
    }
}
extern "C" fn decide(context: *mut c_void, event: *const Event, scope_out: *mut u32) -> u32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: mon_run calls serially with a live Context and stack Event.
        let context = unsafe { &mut *context.cast::<Context>() };
        let event = unsafe { &*event };
        let mut authorizer = context.authorizer.lock().unwrap_or_else(|e| e.into_inner());
        let mut evaluate = || -> Result<(u32, u32), String> {
            if event.has_sequence != 0 {
                authorizer.sequence(event.sequence)?;
            }
            let process = event.process.identity();
            let related = event.related.identity();
            match event.kind {
                5 => {
                    authorizer.exec_project(
                        &process,
                        &related,
                        event.cwd.value(),
                        event.cwd_truncated != 0,
                    )?;
                    return Ok((0, 0));
                }
                6 => {
                    authorizer.fork(&process, &related)?;
                    return Ok((0, 0));
                }
                7 => {
                    authorizer.exit(process.key);
                    return Ok((0, 0));
                }
                _ => {}
            }
            let Some(scope) = authorizer.identify(&process)? else {
                return Ok((0, 0));
            };
            if event.readable == 0 {
                return Ok((0, 0));
            }
            let verdict = authorizer.file(
                scope,
                event.path.value(),
                event.truncated != 0,
                event.regular_file != 0,
                event.links,
            );
            Ok((
                match verdict {
                    Verdict::Deny => 1,
                    Verdict::Ask => 2,
                    Verdict::Review => 4,
                    _ => 0,
                },
                scope.agent as u32 + 1,
            ))
        };
        match evaluate() {
            Ok((verdict, scope)) => {
                unsafe { *scope_out = scope };
                verdict
            }
            Err(error) => {
                context.emit(Record {
                    kind: "coverage_lost",
                    revision: authorizer.revision,
                    pid: event.process.pid,
                    pid_version: event.process.version,
                    agent_id: String::new(),
                    target: error,
                    operation: "health",
                    enforced: false,
                    approval_required: false,
                    ai_review_required: false,
                    response_accepted: false,
                    sequence: None,
                });
                3
            }
        }
    }))
    .unwrap_or(3)
}
extern "C" fn completed(
    context: *mut c_void,
    event: *const Event,
    scope: u32,
    verdict: u32,
    success: u32,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: arguments are produced by mon_run and the immediately preceding decide call.
        let context = unsafe { &*context.cast::<Context>() };
        let event = unsafe { &*event };
        if scope == 0 || (verdict != 1 && verdict != 2 && verdict != 4) {
            return;
        }
        let scope = Scope {
            agent: scope as usize - 1,
            signature_mismatch: false,
            instance: ProcessKey {
                pid: event.process.pid,
                version: event.process.version,
            },
        };
        let authorizer = context.authorizer.lock().unwrap_or_else(|e| e.into_inner());
        context.emit(Record {
            kind: if success != 0 {
                "file_denied"
            } else {
                "response_failed"
            },
            revision: authorizer.revision,
            pid: event.process.pid,
            pid_version: event.process.version,
            agent_id: authorizer.agent_id(scope).into(),
            target: event.path.value().into(),
            operation: match event.kind {
                0 => "open",
                1 => "mmap",
                2 => "readdir",
                3 => "clone",
                4 => "copyfile",
                _ => "unknown",
            },
            enforced: success != 0,
            approval_required: verdict == 2,
            ai_review_required: verdict == 4,
            response_accepted: success != 0,
            sequence: if event.has_sequence != 0 {
                Some(event.sequence)
            } else {
                None
            },
        });
    }));
}
pub fn run(authorizer: FileAuthorizer, runtime_path: std::path::PathBuf) -> Result<(), String> {
    // SAFETY: native helper returns a constant structure size.
    if unsafe { mon_event_size() } != std::mem::size_of::<Event>() {
        return Err("Native event ABI mismatch".into());
    }
    let (sender, receiver) = sync_channel::<Record>(512);
    let lost = Arc::new(AtomicU64::new(0));
    let writer_lost = lost.clone();
    let writer = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        for record in receiver {
            let skipped = writer_lost.swap(0, Ordering::Relaxed);
            if skipped > 0 {
                let _ = writeln!(
                    output,
                    "{}",
                    serde_json::json!({"kind":"audit_gap","lost":skipped,"enforced":false})
                );
            }
            if serde_json::to_writer(&mut output, &record).is_err()
                || writeln!(output).is_err()
                || output.flush().is_err()
            {
                return false;
            }
        }
        true
    });
    let authorizer = Arc::new(Mutex::new(authorizer));
    let publishing = Arc::new(AtomicBool::new(true));
    let publisher_active = publishing.clone();
    let publisher_authorizer = authorizer.clone();
    let listener = crate::transport::bind(&runtime_path)?;
    let publisher = std::thread::spawn(move || {
        crate::transport::serve(
            listener,
            publisher_authorizer,
            publisher_active,
            runtime_path,
        )
    });
    let mut context = Box::new(Context {
        authorizer,
        sender,
        lost,
    });
    // SAFETY: context stays alive for mon_run, which deletes the ES client before returning.
    let result = unsafe { mon_run((&mut *context as *mut Context).cast(), decide, completed) };
    publishing.store(false, Ordering::Release);
    let _ = publisher.join();
    drop(context);
    let writer_ok = writer.join().unwrap_or(false);
    if !writer_ok {
        return Err("Audit output unavailable".into());
    }
    match result {
        0 => Ok(()),
        1 => Err("Invalid Endpoint Security client arguments".into()),
        2 => Err("Endpoint Security internal initialization error".into()),
        3 => Err(
            "Endpoint Security entitlement is missing or not authorized by the signing profile"
                .into(),
        ),
        4 => Err("Full Disk Access authorization is required".into()),
        5 => Err("Endpoint Security requires root privileges".into()),
        6 => Err("Endpoint Security client limit reached".into()),
        100 => Err("Endpoint Security subscription failed".into()),
        200 => Err("Process coverage lost; file enforcement stopped".into()),
        201 => Err("Authorization response failed; file enforcement stopped".into()),
        other => Err(format!("Endpoint Security failed: {other}")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_event_layout_matches_rust() {
        assert_eq!(unsafe { mon_event_size() }, std::mem::size_of::<Event>());
    }
    #[test]
    fn preflight_does_not_claim_active_protection() {
        assert!(!preflight().enforcement_active);
    }
}
