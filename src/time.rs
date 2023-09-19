use std::ffi::{CStr, c_char, c_int, c_long};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(non_camel_case_types)]
type time_t = c_long;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct tm {
    tm_sec   : c_int,
    tm_min   : c_int,
    tm_hour  : c_int,
    tm_mday  : c_int,
    tm_mon   : c_int,
    tm_year  : c_int,
    tm_wday  : c_int,
    tm_yday  : c_int,
    tm_isdst : c_int,
    tm_gmtoff: c_long,
    tm_zone  : *const c_char,
}

extern "C" {
    fn localtime(time: *const time_t) -> *const tm;
    fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const tm) -> usize;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    time: time_t,
}

impl Display for LocalTime {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        unsafe {
            let mut s = [0; 32];
            let tm = *localtime(&self.time);
            strftime(s.as_mut_ptr(), s.len(), b"%d/%b/%Y:%H:%M:%S %z\0".as_ptr() as *const c_char, &tm);
            write!(f, "{}", CStr::from_ptr(s.as_ptr()).to_str().unwrap())
        }
    }
}

impl From<SystemTime> for LocalTime {
    fn from(value: SystemTime) -> Self {
        Self { time: value.duration_since(UNIX_EPOCH).unwrap().as_secs() as time_t }
    }
}

impl LocalTime {
    pub fn now() -> Self {
        Self::from(SystemTime::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::set_var;

    #[test]
    fn test_local_time() {
        let time = LocalTime::from(UNIX_EPOCH);
        set_var("TZ", "UTC");
        assert_eq!(time.to_string(), "01/Jan/1970:00:00:00 +0000");
    }
}
