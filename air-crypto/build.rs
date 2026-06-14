//! Compiles the C23 crypto core and links it into the crate.
//!
//! clang is used explicitly because the system gcc (11.x) does not accept
//! `-std=c23`; clang 18+ does. The core uses C23 features (`constexpr`,
//! `nullptr`).

fn main() {
    cc::Build::new()
        .compiler("clang")
        .std("c23")
        .file("native/pbkdf2_sha1.c")
        .file("native/mic.c")
        .file("native/wep.c")
        .include("include")
        .opt_level(3)
        .warnings(true)
        .compile("air_crypto_c");

    println!("cargo:rerun-if-changed=native/pbkdf2_sha1.c");
    println!("cargo:rerun-if-changed=native/mic.c");
    println!("cargo:rerun-if-changed=include/pbkdf2_sha1.h");
    println!("cargo:rerun-if-changed=include/mic.h");
    println!("cargo:rerun-if-changed=native/wep.c");
    println!("cargo:rerun-if-changed=include/wep.h");
}
