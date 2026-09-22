use std::io::{self, Read};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut input)?;
    if input.len() > 4 * 1024 * 1024 {
        return Err("输入超过 4 MiB".into());
    }
    if let Some(kind) = std::env::args().nth(1) {
        println!(
            "{}",
            serde_json::to_string_pretty(&monitor_core::evidence::audit(&kind, &input)?)?
        );
        return Ok(());
    }
    let replay = serde_json::from_str(&input)?;
    let decisions = monitor_core::replay(replay)?;
    println!("{}", serde_json::to_string_pretty(&decisions)?);
    Ok(())
}
