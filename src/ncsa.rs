use std::collections::HashMap;
use std::ffi::{c_int, c_uint, c_void};
use std::fs::{metadata, read_to_string};
use std::ptr::null;
use std::sync::{Arc, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, UNIX_EPOCH};

#[allow(non_camel_case_types)]
enum EVP_MD {}

#[allow(non_camel_case_types)]
enum EVP_MD_CTX {}

#[link(name = "crypto")]
extern "C" {
    fn EVP_md5() -> *const EVP_MD;
    #[cfg(openssl10)]
    fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
    #[cfg(not(openssl10))]
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    #[cfg(openssl10)]
    fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);
    #[cfg(not(openssl10))]
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, md: *const EVP_MD, engine: *const c_void) -> c_int;
    fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const u8, cnt: usize) -> c_int;
    fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut u8, s: *mut c_uint) -> c_int;
    fn EVP_DecodeBlock(t: *mut u8, f: *const u8, n: c_int) -> c_int;
}

#[allow(non_snake_case)]
#[cfg(openssl10)]
#[inline]
unsafe fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX { EVP_MD_CTX_create() }

#[allow(non_snake_case)]
#[cfg(openssl10)]
#[inline]
unsafe fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX) { EVP_MD_CTX_destroy(ctx) }

#[derive(Clone)]
pub struct Htpasswd {
    entries: Arc<RwLock<Option<HashMap<String, (String, String)>>>>,
}

impl Htpasswd {
    const PATH: &'static str = ".htpasswd";

    fn parse(data: &str) -> HashMap<String, (String, String)> {
        let mut entries = HashMap::new();
        for line in data.split('\n') {
            if let Some((username, salthash)) = line.split_once(':') {
                if salthash.starts_with("$apr1$") {
                    if let Some((salt, hash)) = salthash[6..].split_once('$') {
                        entries.insert(username.into(), (salt.into(), hash.into()));
                    }
                }
            }
        }
        entries
    }

    pub fn new() -> Self {
        let entries = match read_to_string(Self::PATH) {
            Ok(data) => Some(Self::parse(&data)),
            Err(_) => None
        };
        let entries_reader = Arc::new(RwLock::new(entries));
        let entries_writer = entries_reader.clone();
        spawn(move || {
            let mut lastmtime = metadata(Self::PATH).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
            loop {
                sleep(Duration::from_secs(4));
                let mtime = metadata(Self::PATH).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                if mtime == lastmtime { continue }
                lastmtime = mtime;
                match read_to_string(Self::PATH) {
                    Ok(data) => entries_writer.write().unwrap().replace(Self::parse(&data)),
                    Err(_) => entries_writer.write().unwrap().take(),
                };
            }
        });
        Self { entries: entries_reader }
    }

    pub fn contains(&self, username: &str, password: &str) -> bool {
        self.entries.read().unwrap().as_ref().is_some_and(|m| m.get(username).is_some_and(|(salt, hash)| {
            let (key, apr1, salt) = (password.as_bytes(), b"$apr1$", salt.as_bytes());
            unsafe {
                let md5 = EVP_MD_CTX_new();
                EVP_DigestInit_ex(md5, EVP_md5(), null());
                EVP_DigestUpdate(md5, key.as_ptr(), key.len());
                EVP_DigestUpdate(md5, apr1.as_ptr(), apr1.len());
                EVP_DigestUpdate(md5, salt.as_ptr(), salt.len());

                let ctx1 = EVP_MD_CTX_new();
                EVP_DigestInit_ex(ctx1, EVP_md5(), null());
                EVP_DigestUpdate(ctx1, key.as_ptr(), key.len());
                EVP_DigestUpdate(ctx1, salt.as_ptr(), salt.len());
                EVP_DigestUpdate(ctx1, key.as_ptr(), key.len());
                let mut fin = [0; 16];
                let mut s = fin.len() as c_uint;
                EVP_DigestFinal_ex(ctx1, fin.as_mut_ptr(), &mut s);

                let mut n = key.len() as i32;
                while n > 0 {
                    EVP_DigestUpdate(md5, fin.as_ptr(), n.min(16) as usize);
                    n -= 16;
                }

                fin.fill(0);

                let mut i = key.len();
                while i > 0 {
                    EVP_DigestUpdate(md5, if (i & 1) != 0 { fin.as_ptr() } else { key.as_ptr() }, 1);
                    i >>= 1;
                }

                let mut s = fin.len() as c_uint;
                EVP_DigestFinal_ex(md5, fin.as_mut_ptr(), &mut s);

                for i in 0..1000 {
                    EVP_DigestInit_ex(ctx1, EVP_md5(), null());
                    if (i & 1) != 0 {
                        EVP_DigestUpdate(ctx1, key.as_ptr(), key.len());
                    } else {
                        EVP_DigestUpdate(ctx1, fin.as_ptr(), fin.len());
                    }
                    if (i % 3) != 0 {
                        EVP_DigestUpdate(ctx1, salt.as_ptr(), salt.len());
                    }
                    if (i % 7) != 0 {
                        EVP_DigestUpdate(ctx1, key.as_ptr(), key.len());
                    }
                    if (i & 1) != 0 {
                        EVP_DigestUpdate(ctx1, fin.as_ptr(), fin.len());
                    } else {
                        EVP_DigestUpdate(ctx1, key.as_ptr(), key.len());
                    }
                    let mut s = fin.len() as c_uint;
                    EVP_DigestFinal_ex(ctx1, fin.as_mut_ptr(), &mut s);
                }

                EVP_MD_CTX_free(md5);
                EVP_MD_CTX_free(ctx1);

                let itoa64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                let to64 = |mut p: *mut u8, mut v: usize, n: usize| -> *mut u8 {
                    for _ in 0..n {
                        *p = itoa64[v & 0x3F];
                        p = (p as usize + 1) as *mut u8;
                        v >>= 6;
                    }
                    p
                };
                let mut encrypted = [0; 22];
                let mut p = encrypted.as_mut_ptr();
                p = to64(p, (fin[0] as usize) << 16 | (fin[ 6] as usize) << 8 | fin[12] as usize, 4);
                p = to64(p, (fin[1] as usize) << 16 | (fin[ 7] as usize) << 8 | fin[13] as usize, 4);
                p = to64(p, (fin[2] as usize) << 16 | (fin[ 8] as usize) << 8 | fin[14] as usize, 4);
                p = to64(p, (fin[3] as usize) << 16 | (fin[ 9] as usize) << 8 | fin[15] as usize, 4);
                p = to64(p, (fin[4] as usize) << 16 | (fin[10] as usize) << 8 | fin[ 5] as usize, 4);
                _ = to64(p, fin[11] as usize, 2);

                encrypted.eq(hash.as_bytes())
            }
        }))
    }

    pub fn authorize(&self, value: &str) -> bool {
        value.split_once(' ').is_some_and(|(scheme, data)| {
            if !scheme.eq_ignore_ascii_case("Basic") { return false }
            let data = data.as_bytes();
            let mut t = Vec::new();
            t.resize((data.len() + 2) * 3 / 4, 0);
            let n = unsafe { EVP_DecodeBlock(t.as_mut_ptr(), data.as_ptr(), data.len() as c_int) };
            if n < 0 { return false }
            let n = t.iter().take_while(|c| **c != 0).count();
            String::from_utf8_lossy(&t[..n]).split_once(':').is_some_and(|(username, password)| {
                self.contains(username, password)
            })
        })
    }

    pub fn exists(&self) -> bool {
        self.entries.read().unwrap().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htpasswd() {
        let entries = Htpasswd::parse("username:$apr1$v5wryq2g$oliRVLsl/.0Kv77Go9SOQ/");
        let htpasswd = Htpasswd { entries: Arc::new(RwLock::new(Some(entries))) };
        assert!(htpasswd.authorize("Basic dXNlcm5hbWU6cGFzc3dvcmQ="));
    }
}
