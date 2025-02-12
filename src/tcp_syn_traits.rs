use nix::errno::Errno;
use nix::libc::{self, c_int, c_void, socklen_t};
use nix::sys::socket::sockopt;
use nix::{getsockopt_impl, setsockopt_impl};
use std::mem;
use std::os::fd::{AsFd, AsRawFd};

pub const TCP_SAVE_SYN_TRAITS: c_int = 44;
pub const TCP_SYN_TRAITS: c_int = 45;

pub type TraitKey = u8;

macro_rules! bits_to_bytes {
    ($bits:expr) => { $bits / 8 };
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct PktTrait {
    pub _zpad_1: u8,
    pub key: u8,
    pub len: u8,
    pub io_err: u8,
    pub _zpad_2: u32,
    pub val: u64,
}

impl From<TraitKey> for PktTrait {
    fn from(key: TraitKey) -> Self {
        PktTrait {
            key,
            .. Default::default()
        }
    }
}

impl From<(TraitKey, u16)> for PktTrait {
    fn from(pair: (TraitKey, u16)) -> Self {
        PktTrait {
            key: pair.0,
            val: pair.1.into(),
            len: bits_to_bytes!(u16::BITS) as _,
            .. Default::default()
        }
    }
}

impl From<(TraitKey, u32)> for PktTrait {
    fn from(pair: (TraitKey, u32)) -> Self {
        PktTrait {
            key: pair.0,
            val: pair.1.into(),
            len: bits_to_bytes!(u32::BITS) as _,
            .. Default::default()
        }
    }
}

impl From<(TraitKey, u64)> for PktTrait {
    fn from(pair: (TraitKey, u64)) -> Self {
        PktTrait {
            key: pair.0,
            val: pair.1,
            len: bits_to_bytes!(u64::BITS) as _,
            .. Default::default()
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSaveSynTraits;

getsockopt_impl!(
    TcpSaveSynTraits,
    libc::SOL_TCP,
    TCP_SAVE_SYN_TRAITS,
    bool,
    sockopt::GetBool
);

setsockopt_impl!(
    TcpSaveSynTraits,
    libc::SOL_TCP,
    TCP_SAVE_SYN_TRAITS,
    bool,
    sockopt::SetBool
);

#[derive(Clone, Copy)]
pub struct TcpSynTraits<'a>(pub &'a [TraitKey]);

impl nix::sys::socket::GetSockOpt for TcpSynTraits<'_> {
    type Val = Vec<PktTrait>;

    fn get<F: AsFd>(&self, fd: &F) -> nix::Result<Vec<PktTrait>> {
        let n = self.0.len();
        let sz = n * mem::size_of::<PktTrait>();
        let mut traits: Vec<PktTrait> = Vec::with_capacity(n);

        for key in self.0 {
            traits.push(PktTrait {
                key: *key,
                .. Default::default()
            });
        }

        let ffi_ptr = traits.as_mut_ptr() as *mut c_void;
        let mut ffi_len = sz as socklen_t;
        let res = unsafe {
            libc::getsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_TCP,
                TCP_SYN_TRAITS,
                ffi_ptr,
                &mut ffi_len,
            )
        };

        if let Err(err) = Errno::result(res) {
            if err != Errno::EIO {
                return Err(err);
            }
        }

        match ffi_len as usize {
            0 => Ok(vec![]),
            len if len == sz => Ok(traits),
            _ => Err(Errno::EMSGSIZE),
        }
    }
}

// TODO: Merge it with `TcpSynTraits`
#[derive(Clone, Debug)]
pub struct TcpSynTraitsSet<T>(::std::marker::PhantomData<T>);

impl<T> Default for TcpSynTraitsSet<T> {
    fn default() -> Self {
        TcpSynTraitsSet(Default::default())
    }
}

impl<T> nix::sys::socket::SetSockOpt for TcpSynTraitsSet<T>
where
    T: AsRef<[PktTrait]> + Clone,
{
    type Val = T;

    fn set<F: AsFd>(&self, fd: &F, val: &T) -> nix::Result<()> {
        let res = unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_TCP,
                TCP_SYN_TRAITS,
                val.as_ref().as_ptr().cast(),
                mem::size_of_val(val) as libc::socklen_t,
            )
        };
        Errno::result(res).map(drop)
    }
}
