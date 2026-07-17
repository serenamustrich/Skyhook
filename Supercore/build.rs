fn main() {
    println!("cargo:rerun-if-changed=src/platform/macos/mptcp_bridge.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("src/platform/macos/mptcp_bridge.m")
        .flag("-fblocks")
        .flag("-fobjc-arc")
        .warnings(true)
        .compile("skyhook_mptcp_bridge");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Network");
    println!("cargo:rustc-link-lib=framework=Security");
}
