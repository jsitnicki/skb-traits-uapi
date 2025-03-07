use nix::sys::socket::setsockopt;
use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd};

use crate::common::*;
use skb_traits::*;

#[test]
fn can_recv_u16_trait() -> TestResult {
    let obj = load_bpf()?;
    let prog = obj.get_prog_by_name("set_trait")?;

    let s = UdpSocket::bind("127.0.0.1:0")?;
    setsockopt(&s, SoAttachBpf, &prog.as_fd().as_raw_fd())?;

    s.send_to(b"x", s.local_addr()?)?;

    Ok(())
}
