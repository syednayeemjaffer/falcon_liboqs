use std::path::{Path, PathBuf};

fn generate_bindings(includedir: &Path, headerfile: &str, allow_filter: &str, block_filter: &str) {
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .clang_arg(format!("-I{}", includedir.display()))
        .header(
            includedir
                .join("oqs")
                .join(format!("{headerfile}.h"))
                .to_str()
                .unwrap(),
        )
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .size_t_is_usize(true)
        .generate_comments(cfg!(feature = "docs"))
        .allowlist_recursively(false)
        .allowlist_type(allow_filter)
        .allowlist_function(allow_filter)
        .allowlist_var(allow_filter)
        .blocklist_type(block_filter)
        .blocklist_function(block_filter)
        .blocklist_var(block_filter)
        .use_core()
        .ctypes_prefix("::libc")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join(format!("{headerfile}_bindings.rs")))
        .expect("Couldn't write bindings!");
}

//
// ⭐ CHANGED: We completely relax version checking & pkg-config filter
//            Your liboqs is 0.15.x, but oqs-sys expects 0.13.x.
//            This new logic accepts ANY liboqs >= 0.13.
//
fn probe_includedir() -> PathBuf {
    // Prefer system-installed liboqs over vendored
    println!("cargo:rerun-if-env-changed=LIBOQS_NO_VENDOR");
    let force_no_vendor = std::env::var_os("LIBOQS_NO_VENDOR").map_or(false, |v| v != "0");

    // ⭐ CHANGED: Accept ANY version above 0.13.0
    let min_version = "0.13.0";
    let max_version = "1.0.0";

    let config = pkg_config::Config::new()
        .range_version(min_version..max_version)
        .probe("liboqs");

    match config {
        Ok(lib) => {
            println!("cargo:warning=✔ Using system liboqs");
            lib.include_paths.first().cloned().unwrap()
        }
        Err(_) => {
            if force_no_vendor {
                panic!("LIBOQS_NO_VENDOR=1 but system liboqs not found!");
            }

            println!("cargo:warning=⚠ System liboqs not found — falling back to vendored build");
            includedir_from_source()
        }
    }
}

//
// ⭐ CHANGED: This build_from_source is untouched except we DO NOT depend
//            on version matching logic anymore.
//
fn build_from_source() -> PathBuf {
    let mut config = cmake::Config::new("liboqs");
    config.profile("Release");
    config.define("OQS_BUILD_ONLY_LIB", "Yes");

    if cfg!(feature = "non_portable") {
        config.define("OQS_DIST_BUILD", "No");
    } else {
        config.define("OQS_DIST_BUILD", "Yes");
    }

    macro_rules! algorithm_feature {
        ($typ:literal, $feat: literal) => {
            let configflag = format!("OQS_ENABLE_{}_{}", $typ, $feat.to_ascii_uppercase());
            let value = if cfg!(feature = $feat) { "Yes" } else { "No" };
            config.define(&configflag, value);
        };
    }

    // KEMs
    if cfg!(feature = "kems") && !(cfg!(windows) || cfg!(target_arch = "arm")) {
        println!("cargo:rustc-cfg=feature=\"bike\"");
        config.define("OQS_ENABLE_KEM_BIKE", "Yes");
    } else {
        algorithm_feature!("KEM", "bike");
    }
    algorithm_feature!("KEM", "classic_mceliece");
    algorithm_feature!("KEM", "frodokem");
    algorithm_feature!("KEM", "hqc");
    algorithm_feature!("KEM", "kyber");
    algorithm_feature!("KEM", "ml_kem");
    algorithm_feature!("KEM", "ntruprime");

    // signature schemes
    algorithm_feature!("SIG", "cross");
    algorithm_feature!("SIG", "dilithium");
    algorithm_feature!("SIG", "falcon");
    algorithm_feature!("SIG", "mayo");
    algorithm_feature!("SIG", "ml_dsa");
    algorithm_feature!("SIG", "sphincs");
    algorithm_feature!("SIG", "uov");

    if cfg!(windows) {
        config.define("CMAKE_SYSTEM_VERSION", "10.0");
    }

    if cfg!(any(feature = "openssl", feature = "vendored_openssl")) {
        config.define("OQS_USE_OPENSSL", "Yes");
        if cfg!(windows) {
            println!("cargo:rustc-link-lib=libcrypto");
        } else {
            println!("cargo:rustc-link-lib=crypto");
        }
    } else {
        config.define("OQS_USE_OPENSSL", "No");
    }

    if cfg!(feature = "vendored_openssl") {
        let vendored_openssl_root = std::env::var("DEP_OPENSSL_ROOT")
            .expect("vendored_openssl enabled, but DEP_OPENSSL_ROOT missing");
        config.define("OPENSSL_ROOT_DIR", vendored_openssl_root);
    }

    let permit_unsupported = "OQS_PERMIT_UNSUPPORTED_ARCHITECTURE";
    if let Ok(str) = std::env::var(permit_unsupported) {
        config.define(permit_unsupported, str);
    }

    let outdir = config.build();

    let temp_build = outdir.join("build");
    if let Err(e) = std::fs::remove_dir_all(temp_build) {
        println!("cargo:warning=unexpected error while cleaning build files:{e}");
    }

    let libdir = outdir.join("lib");
    let libdir64 = outdir.join("lib64");

    if cfg!(windows) {
        println!("cargo:rustc-link-lib=oqs");
    } else {
        println!("cargo:rustc-link-lib=static=oqs");
    }

    if cfg!(windows) {
        println!("cargo:rustc-link-lib=advapi32");
    }

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-search=native={}", libdir64.display());

    outdir
}

fn includedir_from_source() -> PathBuf {
    let outdir = build_from_source();
    outdir.join("include")
}

fn main() {
    bindgen::clang_version();

    let includedir = probe_includedir();
    let gen_bindings = |file, allow, block| {
        generate_bindings(&includedir, file, allow, block)
    };

    gen_bindings("common", "OQS_.*", "");
    gen_bindings("rand", "OQS_(randombytes|RAND).*", "");
    gen_bindings("kem", "OQS_KEM.*", "");
    gen_bindings("sig", "OQS_SIG.*", "OQS_SIG_STFL.*");

    build_deps::rerun_if_changed_paths("liboqs/src/**/*").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src/*").unwrap();
}
