use nix::libc::{c_void, socklen_t};
use nix::sys::socket::sockopt;

use std::mem::{self, MaybeUninit};

pub struct GetBytes<T: AsMut<[u8]>> {
    len: socklen_t,
    val: MaybeUninit<T>,
}

impl<T: AsMut<[u8]>> sockopt::Get<Vec<u8>> for GetBytes<T> {
    fn uninit() -> Self {
        GetBytes {
            len: mem::size_of::<T>() as socklen_t,
            val: MaybeUninit::uninit(),
        }
    }

    fn ffi_ptr(&mut self) -> *mut c_void {
        self.val.as_mut_ptr().cast()
    }

    fn ffi_len(&mut self) -> *mut socklen_t {
        &mut self.len
    }

    unsafe fn assume_init(self) -> Vec<u8> {
        let len = self.len as usize;
        let mut v = unsafe { self.val.assume_init() };

        v.as_mut()[0..len].to_vec()
    }
}
