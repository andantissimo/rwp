use std::process::Command;

#[allow(dead_code)]
fn cfg_if_version<F: FnOnce(&str) -> bool>(id: &str, pkg: &str, f: F) {
    if Command::new("pkg-config").args(["--modversion", pkg])
        .output().is_ok_and(|o| f(&String::from_utf8_lossy(&o.stdout))) {
        println!("cargo:rustc-cfg={}", id);
    }
}

fn main() {
    #[cfg(feature = "htpasswd")]
    cfg_if_version("openssl10", "openssl", |v| v.starts_with("1.0."));
}
