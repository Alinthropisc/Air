




#[macro_export]
macro_rules! allege {
    ($cond:expr) => {
        if !($cond) {
            panic!("[ ETA ]: Air ALLEGE Failed: {} at {}:{}",stringify!($cond),file!(),line!());
        }
    };
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            panic!("[ ETA ]: Air ALLEGE Failed: {} — {}", stringify!($cond), $msg);
        }
    };
}



#[macro_export]
macro_rules! require {
    ($cond:expr) => {
        debug_assert!($cond,"[ ETA ]: Air Pre-condition Failed: {}",stringify!($cond));
    };
}


#[macro_export]
macro_rules! ensure_post {
    ($cond:expr) => {
        debug_assert!($cond, "[ ETA ]: Air Post-condition Failed: {}",stringify!($cond));
    };
}


#[macro_export]
macro_rules! air_warn {
    ($result:expr) => {
        match $result {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("[ ETA ]: Air Warning at {}:{} → {:?}",file!(), line!(), e);
                None
            }
        }
    };
}


#[macro_export]
macro_rules! array_count {
    ($arr:expr) => {
        ($arr).len()
    };
}


#[inline(always)]
pub fn likely(b: bool) -> bool { 
    b 
}

#[inline(always)]
pub fn unlikely(b: bool) -> bool { 
    b 
}
































































