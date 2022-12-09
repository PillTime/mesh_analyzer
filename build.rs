use std::{
    fs::{create_dir_all, File},
    path::Path,
    process::Command,
};

use bindgen::{builder, callbacks::ParseCallbacks};
use libbpf_cargo::SkeletonBuilder;

#[derive(Debug)]
struct ActionCallbacks;

impl ParseCallbacks for ActionCallbacks {
    fn add_derives(&self, name: &str) -> Vec<String> {
        if name == "Action" {
            vec!["Deserialize".into(), "Serialize".into()]
        } else {
            vec![]
        }
    }
}

fn main() {
    let bpf = "./src/bpf".to_string();
    let out = format!("{bpf}/.output");
    let vml = format!("{bpf}/vmlinux.h");
    let src = format!("{bpf}/tracer.bpf.c");
    let hdr = format!("{bpf}/tracer.bpf.h");
    let skl = format!("{out}/tracer.skel.rs");
    let bnd = "./src/binds.rs".to_string();
    println!("cargo:rerun-if-changed={vml}");
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed={hdr}");

    // bpftool
    if !Path::new(&vml).exists() {
        let vmlinux = File::create(&vml).expect("create vmlinux.h file");
        Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/mac80211",
                "format",
                "c",
            ])
            .stdout(vmlinux)
            .status()
            .expect("insert vmlinux.h content");
    }

    // libbpf-cargo
    create_dir_all(&out).expect("create folder for bpf output");
    SkeletonBuilder::new(&src)
        .generate(&skl)
        .expect("generate bpf skeleton");

    // bindgen
    builder()
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .header(&hdr)
        .generate_comments(false)
        .allowlist_type("Action")
        .allowlist_type("Event")
        .allowlist_var("HAS_ADDR4")
        .allowlist_var("HAS_QOS")
        .allowlist_var("CHECK_QOS")
        .allowlist_var("HDR_SIZE_3ADDR")
        .allowlist_var("HDR_SIZE_4ADDR")
        .raw_line("use serde::{Deserialize, Serialize};")
        .parse_callbacks(Box::new(ActionCallbacks))
        .generate()
        .expect("generate ffi bindings")
        .write_to_file(&bnd)
        .expect("write ffi bindings");
}
