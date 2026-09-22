use monitor_runtime::{
    scan::{self, Source},
    watch,
};
use std::{io::Write, path::PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("monitor") if args.len() == 1 => {
            let audit = std::sync::Arc::new(monitor_runtime::audit::Audit::open(
                &monitor_runtime::audit::Audit::default_path()?,
            )?);
            let state = std::sync::Arc::new(std::sync::Mutex::new(
                monitor_runtime::sensor::SensorSnapshot::default(),
            ));
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|e|e.to_string())?.block_on(async {
                let task=tokio::spawn(monitor_runtime::sensor::run(state.clone(),audit));
                let mut interval=tokio::time::interval(std::time::Duration::from_secs(3));
                let mut stop=std::pin::pin!(tokio::signal::ctrl_c());
                loop {tokio::select!{
                    _=&mut stop=>break,
                    _=interval.tick()=>println!("{}",serde_json::to_string(&*state.lock().map_err(|_|"状态锁异常")?).map_err(|e|e.to_string())?),
                }}
                task.abort(); let _=task.await; Ok(())
            })
        }
        Some("scan" | "watch") => {
            let sources = match args.as_slice() {
                [_] => scan::default_sources(),
                [_, kind, root] if kind == "trae" || kind == "zcode" => vec![Source {
                    kind: kind.clone(),
                    root: PathBuf::from(root),
                }],
                _ => return Err(usage()),
            };
            let emit = |report| {
                let mut out = std::io::stdout().lock();
                serde_json::to_writer(&mut out, &report).map_err(|e| e.to_string())?;
                writeln!(&mut out).map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())
            };
            if args[0] == "watch" {
                watch::watch(&sources, emit)
            } else {
                emit(scan::scan(&sources))
            }
        }
        _ => Err(usage()),
    }
}
fn usage() -> String {
    "用法: monitor-service monitor\n      monitor-service scan|watch [trae|zcode 证据根目录]".into()
}
