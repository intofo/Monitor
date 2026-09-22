fn main() {
    println!("cargo:rerun-if-changed=native/endpoint.c");
    println!("cargo:rerun-if-changed=native/endpoint.h");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/endpoint.c")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=12.0")
            .warnings_into_errors(true)
            .compile("monitor_endpoint");
        println!("cargo:rustc-link-lib=EndpointSecurity");
        println!("cargo:rustc-link-lib=bsm");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}
