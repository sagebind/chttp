#![allow(unsafe_code)]

use curl_sys::*;
use std::ptr::NonNull;

pub enum ShareData {
    Cookie,
    Dns,
    SslSession,
    Connect,
}

impl ShareData {
    fn raw(&self) -> curl_lock_data {
        match self {
            Self::Cookie => CURL_LOCK_DATA_COOKIE,
            Self::Dns => CURL_LOCK_DATA_DNS,
            Self::SslSession => CURL_LOCK_DATA_SSL_SESSION,
            Self::Connect => CURL_LOCK_DATA_CONNECT,
        }
    }
}

/// Safe wrapper around a libcurl CURLSH handle.
///
/// While this wrapper is safe, fully using it is not, because it is very
/// difficult to track the lifetime of a share after adding it to an easy
/// handle. The API would have to be redesigned before it could ever be
/// upstreamed.
pub struct Share {
    handle: NonNull<CURLSH>,
}

impl Share {
    pub fn new() -> Self {
        Self {
            handle: NonNull::new(unsafe {
                curl_share_init()
            }).expect("curl_share_init returned null")
        }
    }

    pub unsafe fn from_raw(raw: *mut CURLSH) -> Self {
        Self {
            handle: NonNull::new_unchecked(raw),
        }
    }

    pub fn share(&mut self, data: ShareData) -> Result<(), Error> {
        unsafe {
            self.setopt(CURLSHOPT_SHARE, data.raw())
        }
    }

    pub fn unshare(&mut self, data: ShareData) -> Result<(), Error> {
        unsafe {
            self.setopt(CURLSHOPT_UNSHARE, data.raw())
        }
    }

    unsafe fn setopt<T>(&mut self, option: CURLSHoption, parameter: T) -> Result<(), Error> {
        match curl_share_setopt(self.as_ptr(), option, parameter) {
            CURLSHE_OK => Ok(()),
            code => Err(Error { code }),
        }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut CURLSH {
        self.handle.as_ptr()
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        unsafe {
            curl_share_cleanup(self.as_ptr());
        }
    }
}

pub struct Error {
    code: CURLSHcode,
}
