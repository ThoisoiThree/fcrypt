use std::path::{Path, PathBuf};
use std::process::Command;

const LIBOQS_REPOSITORY: &str = "https://github.com/tectonic-labs/liboqs.git";
const LIBOQS_REVISION: &str = "282809f06dccf6893980035cb11f319684d10d52";

fn verify_liboqs_revision(path: &Path) -> Result<(), String> {
    if !path.join("CMakeLists.txt").is_file() {
        return Err("CMakeLists.txt is missing".to_string());
    }

    let output = Command::new("git")
        .args([
            "-C",
            path.to_str().unwrap(),
            "rev-parse",
            "--verify",
            "HEAD",
        ])
        .output()
        .map_err(|error| format!("failed to execute git: {error}"))?;

    if !output.status.success() {
        return Err("source directory is not a verifiable Git checkout".to_string());
    }

    let actual = String::from_utf8(output.stdout)
        .map_err(|_| "git returned a non-UTF-8 revision".to_string())?;
    let actual = actual.trim();
    if actual != LIBOQS_REVISION {
        return Err(format!(
            "revision mismatch: expected {LIBOQS_REVISION}, found {actual}"
        ));
    }

    let status = Command::new("git")
        .args([
            "-C",
            path.to_str().unwrap(),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ])
        .output()
        .map_err(|error| format!("failed to inspect the liboqs worktree: {error}"))?;
    if !status.status.success() {
        return Err("git could not inspect the liboqs worktree".to_string());
    }
    if !status.stdout.is_empty() {
        return Err("source tree differs from the pinned commit".to_string());
    }

    Ok(())
}

fn run_git(args: &[&str], operation: &str) {
    let status = Command::new("git")
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("Failed to execute git while {operation}: {error}"));
    assert!(status.success(), "Git failed while {operation}");
}

/// Returns the path to liboqs source, downloading it to OUT_DIR if necessary.
/// Every source tree, including an already populated cache, must resolve to the
/// release-pinned commit before any of its C code is compiled.
fn get_liboqs_source_dir() -> PathBuf {
    let local_liboqs = Path::new("liboqs");

    if local_liboqs.exists() {
        verify_liboqs_revision(local_liboqs)
            .unwrap_or_else(|error| panic!("Refusing unverified local liboqs source: {error}"));
        return local_liboqs.to_path_buf();
    }

    // Otherwise, download to OUT_DIR
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let liboqs_dir = out_dir.join("liboqs-src");

    if liboqs_dir.exists() {
        match verify_liboqs_revision(&liboqs_dir) {
            Ok(()) => return liboqs_dir,
            Err(error) => {
                println!("cargo:warning=discarding unverified cached liboqs source: {error}");
                std::fs::remove_dir_all(&liboqs_dir)
                    .expect("Failed to remove unverified cached liboqs source");
            }
        }
    }

    println!("cargo:warning=fetching pinned liboqs revision {LIBOQS_REVISION} from git...");
    let liboqs_dir_str = liboqs_dir.to_str().unwrap();
    run_git(
        &["init", "--quiet", liboqs_dir_str],
        "initializing liboqs checkout",
    );
    run_git(
        &[
            "-C",
            liboqs_dir_str,
            "fetch",
            "--quiet",
            "--depth",
            "1",
            LIBOQS_REPOSITORY,
            LIBOQS_REVISION,
        ],
        "fetching pinned liboqs revision",
    );
    run_git(
        &[
            "-C",
            liboqs_dir_str,
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ],
        "checking out pinned liboqs revision",
    );
    verify_liboqs_revision(&liboqs_dir)
        .unwrap_or_else(|error| panic!("Downloaded liboqs source failed verification: {error}"));

    println!("cargo:warning=verified liboqs revision {LIBOQS_REVISION}");
    liboqs_dir
}

fn generate_bindings(includedir: &Path, headerfile: &str, allow_filter: &str, block_filter: &str) {
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let mut builder = bindgen::Builder::default()
        .clang_arg(format!("-I{}", includedir.display()))
        .header(
            includedir
                .join("oqs")
                .join(format!("{headerfile}.h"))
                .to_str()
                .unwrap(),
        );

    // Add Emscripten system headers for WASM targets
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.starts_with("wasm32") {
        if let Ok(emsdk) = std::env::var("EMSDK") {
            // Add Emscripten system include paths
            let emsdk_include = format!("{}/upstream/emscripten/cache/sysroot/include", emsdk);
            builder = builder.clang_arg(format!("-I{}", emsdk_include));

            // Set the target for clang
            builder = builder.clang_arg("--target=wasm32-unknown-emscripten");
        }
    }

    builder
        // Options
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .size_t_is_usize(true)
        // Don't generate docs unless enabled
        // Otherwise it breaks tests
        .generate_comments(cfg!(feature = "docs"))
        // Allowlist/blocklist OQS stuff
        .allowlist_recursively(false)
        .allowlist_type(allow_filter)
        .allowlist_function(allow_filter)
        .allowlist_var(allow_filter)
        .blocklist_type(block_filter)
        .blocklist_function(block_filter)
        .blocklist_var(block_filter)
        // Use core and libc
        .use_core()
        .ctypes_prefix("::libc")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join(format!("{headerfile}_bindings.rs")))
        .expect("Couldn't write bindings!");
}

fn build_from_source(liboqs_src: &Path) -> PathBuf {
    let mut config = cmake::Config::new(liboqs_src);
    config.profile("Release");
    config.define("OQS_BUILD_ONLY_LIB", "Yes");

    // Detect WASM target and configure for Emscripten
    let target = std::env::var("TARGET").unwrap_or_default();
    let is_wasm = target.starts_with("wasm32");

    if is_wasm {
        // Use Ninja generator as recommended for Emscripten
        // (emcmake cmake -GNinja ...)
        config.generator("Ninja");

        // Set Emscripten toolchain file if EMSDK is available
        if let Ok(emsdk) = std::env::var("EMSDK") {
            let toolchain = format!(
                "{}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake",
                emsdk
            );
            config.define("CMAKE_TOOLCHAIN_FILE", &toolchain);
        }

        // Force OpenSSL OFF for WASM (as per liboqs issue #1199)
        config.define("OQS_USE_OPENSSL", "OFF");

        // Permit unsupported architecture for WASM
        config.define("OQS_PERMIT_UNSUPPORTED_ARCHITECTURE", "ON");

        println!("cargo:warning=Building for WASM with Emscripten");
    }

    if cfg!(feature = "non_portable") {
        // Build with CPU feature detection or just enable whatever is available for this CPU
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
    // BIKE is not supported on Windows or Arm32, so if either is in the mix,
    // have it be opt-in explicitly except through the default kems feature.
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
    algorithm_feature!("SIG", "slh_dsa");
    algorithm_feature!("SIG", "sphincs");
    algorithm_feature!("SIG", "uov");

    if cfg!(windows) {
        // Select the latest available Windows SDK
        // SDK version 10.0.17763.0 seems broken
        config.define("CMAKE_SYSTEM_VERSION", "10.0");
    }

    // link the openssl libcrypto
    // Skip OpenSSL for WASM builds as it's not compatible
    if !is_wasm && cfg!(any(feature = "openssl", feature = "vendored_openssl")) {
        config.define("OQS_USE_OPENSSL", "Yes");
        if cfg!(windows) {
            // Windows doesn't prefix with lib
            println!("cargo:rustc-link-lib=libcrypto");
        } else {
            println!("cargo:rustc-link-lib=crypto");
        }
    } else {
        config.define("OQS_USE_OPENSSL", "No");
    }

    // let the linker know where to search for openssl libcrypto
    // Skip OpenSSL configuration for WASM builds
    if !is_wasm && cfg!(feature = "vendored_openssl") {
        // DEP_OPENSSL_ROOT is set by openssl-sys if a vendored build was used.
        // We point CMake towards this so that the vendored openssl is preferred
        // over the system openssl.
        let vendored_openssl_root = std::env::var("DEP_OPENSSL_ROOT")
            .expect("The `vendored_openssl` feature was enabled, but DEP_OPENSSL_ROOT was not set");
        config.define("OPENSSL_ROOT_DIR", vendored_openssl_root);
    } else if !is_wasm && cfg!(feature = "openssl") {
        println!("cargo:rerun-if-env-changed=OPENSSL_ROOT_DIR");
        if let Ok(dir) = std::env::var("OPENSSL_ROOT_DIR") {
            let dir = Path::new(&dir).join("lib");
            println!("cargo:rustc-link-search={}", dir.display());
        } else if cfg!(target_os = "macos") {
            // Try to find OpenSSL via Homebrew on macOS
            if let Ok(output) = Command::new("brew").args(["--prefix", "openssl"]).output() {
                if output.status.success() {
                    let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let lib_dir = Path::new(&prefix).join("lib");
                    if lib_dir.exists() {
                        config.define("OPENSSL_ROOT_DIR", &prefix);
                        println!("cargo:rustc-link-search={}", lib_dir.display());
                    } else {
                        println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
                    }
                } else {
                    println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
                }
            } else {
                println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
            }
        } else if cfg!(target_os = "windows") {
            println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
        }
    }

    let permit_unsupported = "OQS_PERMIT_UNSUPPORTED_ARCHITECTURE";
    if let Ok(str) = std::env::var(permit_unsupported) {
        config.define(permit_unsupported, str);
    }

    // build the default (install) target.
    let outdir = config.build();

    // remove the build folder
    let temp_build = outdir.join("build");
    if let Err(e) = std::fs::remove_dir_all(temp_build) {
        println!(
            "cargo:warning=unexpected error while cleaning build files:{}",
            e
        );
    }

    // lib is installed to $outdir/lib or lib64, depending on CMake conventions
    let libdir = outdir.join("lib");
    let libdir64 = outdir.join("lib64");

    if cfg!(windows) {
        // Static linking doesn't work on Windows
        println!("cargo:rustc-link-lib=oqs");
    } else {
        // Statically linking makes it easier to use the sys crate
        println!("cargo:rustc-link-lib=static=oqs");
    }

    if cfg!(windows) {
        // Explicitly link against advapi32. See https://github.com/rust-lang/rust/issues/140555
        println!("cargo:rustc-link-lib=advapi32");
    }

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-search=native={}", libdir64.display());

    outdir
}

fn includedir_from_source() -> PathBuf {
    let liboqs_src = get_liboqs_source_dir();
    let outdir = build_from_source(&liboqs_src);
    outdir.join("include")
}

fn probe_includedir() -> PathBuf {
    if cfg!(feature = "vendored") {
        return includedir_from_source();
    }

    println!("cargo:rerun-if-env-changed=LIBOQS_NO_VENDOR");
    let force_no_vendor = std::env::var_os("LIBOQS_NO_VENDOR").is_some_and(|v| v != "0");

    let version = env!("CARGO_PKG_VERSION");
    let (_, liboqs_version) = version.split_once("+liboqs-").unwrap();
    let &[major_version, minor_version, _] =
        liboqs_version.split('.').collect::<Vec<_>>().as_slice()
    else {
        panic!("Failed to parse target liboqs version");
    };
    let minor_num: usize = minor_version.parse().unwrap();
    let upper_bound = format!("{}.{}.0", major_version, minor_num + 1);
    let config = pkg_config::Config::new()
        .range_version(liboqs_version..upper_bound.as_str())
        .probe("liboqs");

    match config {
        Ok(lib) => lib.include_paths.first().cloned().unwrap(),
        _ => {
            if force_no_vendor {
                panic!("The env variable LIBOQS_NO_VENDOR has been set but a suitable system liboqs could not be found.");
            }

            includedir_from_source()
        }
    }
}

fn main() {
    // Check if clang is available before compiling anything.
    bindgen::clang_version();

    let includedir = probe_includedir();
    let gen_bindings = |file, allow_filter, block_filter| {
        generate_bindings(&includedir, file, allow_filter, block_filter)
    };

    gen_bindings("common", "OQS_.*", "");
    gen_bindings("rand", "OQS_(randombytes|RAND).*", "");
    gen_bindings("kem", "OQS_KEM.*", "");
    gen_bindings("sig", "OQS_SIG.*", "OQS_SIG_STFL.*");

    // Only watch for changes if local submodule exists (not when downloaded)
    if Path::new("liboqs/CMakeLists.txt").exists() {
        build_deps::rerun_if_changed_paths("liboqs/src/**/*").unwrap();
        build_deps::rerun_if_changed_paths("liboqs/src").unwrap();
        build_deps::rerun_if_changed_paths("liboqs/src/*").unwrap();
    }
}
