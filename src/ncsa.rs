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
unsafe fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX {
    EVP_MD_CTX_create()
}

#[allow(non_snake_case)]
#[cfg(openssl10)]
#[inline]
unsafe fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX) {
    EVP_MD_CTX_destroy(ctx)
}

#[derive(Clone)]
pub struct Htpasswd {
    entries: Arc<RwLock<HashMap<String, (String, String)>>>,
}

impl Htpasswd {
    pub fn new() -> Htpasswd {
        let path = ".htpasswd";
        let mut entries = HashMap::new();
        Self::parse(&read_to_string(path).unwrap_or_default(), &mut entries);
        let entries_reader = Arc::new(RwLock::new(entries));
        let entries_writer = entries_reader.clone();
        spawn(move || {
            let mut lastmtime = metadata(path).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
            loop {
                sleep(Duration::from_secs(4));
                let mtime = metadata(path).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                if mtime == lastmtime { continue }
                lastmtime = mtime;
                let mut entries = entries_writer.write().unwrap();
                entries.clear();
                Self::parse(&read_to_string(path).unwrap_or_default(), &mut entries);
            }
        });
        Htpasswd { entries: entries_reader }
    }

    fn parse(data: &str, entries: &mut HashMap<String, (String, String)>) {
        for line in data.split('\n') {
            if let Some((username, salthash)) = line.split_once(':') {
                if salthash.starts_with("$apr1$") {
                    if let Some((salt, hash)) = salthash[6..].split_once('$') {
                        entries.insert(username.into(), (salt.into(), hash.into()));
                    }
                }
            }
        }
    }

    pub fn contains(&self, username: &str, password: &str) -> bool {
        if let Some((salt, hash)) = self.entries.read().unwrap().get(username) {
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

                return encrypted.eq(hash.as_bytes())
            }
        }
        false
    }

    pub fn authorize(&self, value: &str) -> bool {
        if let Some((scheme, data)) = value.split_once(' ') {
            if !scheme.eq_ignore_ascii_case("Basic") { return false }
            let data = data.as_bytes();
            let mut t = Vec::new();
            t.resize((data.len() + 2) * 3 / 4, 0);
            unsafe {
                let n = EVP_DecodeBlock(t.as_mut_ptr(), data.as_ptr(), data.len() as c_int);
                if n < 0 { return false }
                t.resize(n as usize, 0);
                if let Ok(credentials) = String::from_utf8(t) {
                    if let Some((username, password)) = credentials.split_once(':') {
                        return self.contains(username, password)
                    }
                }
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}
