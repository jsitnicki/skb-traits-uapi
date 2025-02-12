use nix::{self, sockopt_impl, setsockopt_impl};
use nix::libc;

sockopt_impl!(
    SoAttachBpf,
    SetOnly,
    libc::SOL_SOCKET,
    libc::SO_ATTACH_BPF,
    libc::c_int
);
