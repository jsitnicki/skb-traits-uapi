use nix::libc;
use nix::sys::socket::sockopt;
use nix::{getsockopt_impl, setsockopt_impl};

use crate::sockopt_ext;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSaveSyn;

getsockopt_impl!(
    TcpSaveSyn,
    libc::SOL_TCP,
    libc::TCP_SAVE_SYN,
    bool,
    sockopt::GetBool
);

setsockopt_impl!(
    TcpSaveSyn,
    libc::SOL_TCP,
    libc::TCP_SAVE_SYN,
    bool,
    sockopt::SetBool
);

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSavedSyn;

getsockopt_impl!(
    TcpSavedSyn,
    libc::SOL_TCP,
    libc::TCP_SAVED_SYN,
    Vec<u8>,
    sockopt_ext::GetBytes<[u8; 64]>
);
