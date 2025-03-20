use nix::cmsg_space;
use nix::libc::{self, cmsghdr};
use nix::sys::socket::{
    getsockopt, recvmsg, setsockopt, ControlMessageOwned, MsgFlags, UnknownCmsg,
};
use std::io::IoSliceMut;
use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd};

use crate::common::*;
use skb_traits::*;

#[test]
fn can_get_set_rcv_pkt_traits_sockopt() -> TestResult {
    let s = UdpSocket::bind("127.0.0.1:0")?;

    assert_eq!(Ok(false), getsockopt(&s, RcvPktTraits));
    setsockopt(&s, RcvPktTraits, &true)?;
    assert_eq!(Ok(true), getsockopt(&s, RcvPktTraits));
    setsockopt(&s, RcvPktTraits, &false)?;
    assert_eq!(Ok(false), getsockopt(&s, RcvPktTraits));

    Ok(())
}

#[test]
fn can_recv_traits() -> TestResult {
    let obj = load_bpf()?;
    let prog = obj.get_prog_by_name("set_trait")?;

    let s = UdpSocket::bind("127.0.0.1:0")?;
    setsockopt(&s, SoAttachBpf, &prog.as_fd().as_raw_fd())?;
    setsockopt(&s, RcvPktTraits, &true)?;

    s.send_to(b"x", s.local_addr()?)?;

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cbuf = cmsg_space!([u8; 16 + 8 * 64]);

    let msg = recvmsg::<()>(s.as_raw_fd(), &mut iov, Some(&mut cbuf), MsgFlags::empty())?;
    assert_eq!(msg.flags.intersects(MsgFlags::MSG_CTRUNC), false);

    let mut traits_data = None;
    for cm in msg.cmsgs()? {
        if let ControlMessageOwned::Unknown(UnknownCmsg {
            cmsg_header:
                cmsghdr {
                    cmsg_len: _, // verified later
                    cmsg_level: libc::SOL_SOCKET,
                    cmsg_type: SCM_PKT_TRAITS,
                },
            data_bytes: data,
        }) = cm
        {
            traits_data = Some(data);
        }
    }

    assert!(traits_data.is_some());

    let traits = PktTraits::try_from(traits_data.unwrap())?;
    assert_eq!(Ok(Some(TraitValue::U16(0xcf))), traits.get(42));

    Ok(())
}
