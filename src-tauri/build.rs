fn main() {
    println!("cargo:rerun-if-env-changed=MONITOR_RELEASE_DATE");
    let release_date =
        std::env::var("MONITOR_RELEASE_DATE").unwrap_or_else(|_| "2026-09-22".into());
    assert!(
        release_date.len() == 10
            && release_date.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            }),
        "MONITOR_RELEASE_DATE must use YYYY-MM-DD"
    );
    println!("cargo:rustc-env=MONITOR_RELEASE_DATE={release_date}");
    println!("cargo:rerun-if-changed=native/system_extensions.m");
    println!("cargo:rerun-if-changed=native/about.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/system_extensions.m")
            .file("native/about.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=12.0")
            .warnings_into_errors(true)
            .compile("monitor_system_extensions");
        println!("cargo:rustc-link-lib=framework=SystemExtensions");
        println!("cargo:rustc-link-lib=framework=NetworkExtension");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
    tauri_build::build()
}
