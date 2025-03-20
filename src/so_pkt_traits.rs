use nix::libc::{self, c_int};
use nix::{self, getsockopt_impl, setsockopt_impl, sockopt_impl};

pub const SO_RCV_PKT_TRAITS: c_int = 82;
pub const SO_PKT_TRAITS: c_int = 83;
pub const SCM_PKT_TRAITS: c_int = SO_PKT_TRAITS;

sockopt_impl!(
    RcvPktTraits,
    Both,
    libc::SOL_SOCKET,
    SO_RCV_PKT_TRAITS,
    bool
);
