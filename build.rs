use std::process::Command;

#[allow(dead_code)]
fn pkg_config(opt: &str, pkg: &str) -> Option<String> {
    Command::new("pkg-config").args([opt, pkg]).output()
        .ok().and_then(|o| String::from_utf8(o.stdout).ok())
}

fn main() {
    #[cfg(feature = "htpasswd")]
    if pkg_config("--modversion", "openssl").is_some_and(|v| v.starts_with("1.0.")) {
        println!("cargo:rustc-cfg={}", "openssl10")
    }
}
