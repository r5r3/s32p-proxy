use std::{env, fs, path::PathBuf};

fn main() {
    // Only do Lustre binding work when the feature is enabled.
    if env::var_os("CARGO_FEATURE_LUSTRE").is_none() {
        return;
    }

    // Locate liblustreapi + headers using pkg-config (needs lustre-client devel package).
    let lib = pkg_config::Config::new()
        .probe("lustre")
        .expect("pkg-config could not find 'lustre' (install lustre-devel / lustre-client-devel, and ensure pkg-config paths are set)");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let wrapper_h = out_dir.join("lustre_wrapper.h");
    fs::write(&wrapper_h, "#include <lustre/lustreapi.h>\n")
        .expect("failed to write lustre_wrapper.h");

    // Pass include paths to clang for bindgen.
    let mut clang_args: Vec<String> = Vec::new();
    for inc in &lib.include_paths {
        clang_args.push(format!("-I{}", inc.display()));
    }

    let bindings = bindgen::Builder::default()
        .header(wrapper_h.to_string_lossy())
        .clang_args(clang_args)
        // Keep the surface area small: only what we need for lockahead via llapi_ladvise.
        .allowlist_function("llapi_ladvise.*")
        .allowlist_type("llapi_lu_ladvise.*")
        .allowlist_type("lu_ladvise_type")
        .rustified_enum("lu_ladvise_type")
        .allowlist_type("ladvise_flag")
        .rustified_enum("ladvise_flag")
        .derive_default(true)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed for lustreapi.h");

    let out_bindings = out_dir.join("lustre_bindings.rs");
    bindings
        .write_to_file(&out_bindings)
        .expect("failed to write lustre_bindings.rs");

    // Re-run if build script changes.
    println!("cargo:rerun-if-changed=build.rs");
}
