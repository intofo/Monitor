fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--check" {
        println!(
            "{}",
            serde_json::to_string(&monitor_enforcer::native::preflight())
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if !args.is_empty() && (args.len() != 2 || args[0] != "--policy") {
        return Err("Usage: monitor-enforcer --check | --policy /root-owned/policy.json".into());
    }
    let preflight = monitor_enforcer::native::preflight();
    if !preflight.endpoint_security_entitlement {
        return Err(
            "Endpoint Security entitlement/signing profile is required; no enforcement started"
                .into(),
        );
    }
    if !preflight.privileged {
        return Err("The system extension must be launched by macOS with root privileges".into());
    }
    let path = args.get(1).map(std::path::Path::new).unwrap_or_else(|| {
        std::path::Path::new("/Library/Application Support/Monitor/Enforcement/policy.json")
    });
    let snapshot = monitor_enforcer::snapshot::read(path)?;
    monitor_enforcer::native::run(
        monitor_enforcer::FileAuthorizer::new(snapshot)?,
        path.with_file_name("runtime.sock"),
    )
}
#[cfg(not(target_os = "macos"))]
fn run() -> Result<(), String> {
    Err("Endpoint Security requires macOS".into())
}
