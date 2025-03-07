use nix::errno::Errno;
use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockProtocol,
    SockType, SockaddrStorage,
};
use nix::{libc, setsockopt_impl};
use std::mem;
use std::net::Ipv4Addr;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use crate::common::*;
use skb_traits::*;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSaveSynTraitsInt;

setsockopt_impl!(
    TcpSaveSynTraitsInt,
    libc::SOL_TCP,
    TCP_SAVE_SYN_TRAITS,
    usize,
    sockopt::SetUsize
);

const LOOPBACK_V4: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 0);

#[test]
pub fn can_toggle_save_syn_traits_flag() -> TestResult {
    let ln = TcpListener::bind("127.0.0.1:0")?;

    assert_eq!(Ok(false), getsockopt(&ln, TcpSaveSynTraits));
    assert_eq!(Ok(()), setsockopt(&ln, TcpSaveSynTraits, &true));
    assert_eq!(Ok(true), getsockopt(&ln, TcpSaveSynTraits));
    assert_eq!(Ok(()), setsockopt(&ln, TcpSaveSynTraits, &false));
    assert_eq!(Ok(false), getsockopt(&ln, TcpSaveSynTraits));

    Ok(())
}

#[test]
pub fn can_set_save_syn_traits_flag_only_to_zero_or_one() -> TestResult {
    let ln = TcpListener::bind("127.0.0.1:0")?;

    assert_eq!(Ok(()), setsockopt(&ln, TcpSaveSynTraitsInt, &0));
    assert_eq!(Ok(()), setsockopt(&ln, TcpSaveSynTraitsInt, &1));
    assert_eq!(Err(Errno::EINVAL), setsockopt(&ln, TcpSaveSynTraitsInt, &2));

    Ok(())
}

#[ignore]
#[test]
pub fn cant_enable_trait_saving_on_connected_socket() -> TestResult {
    todo!()
}

#[test]
pub fn traits_empty_when_not_enabled() -> TestResult {
    let obj = load_bpf()?;
    let prog = obj.get_prog_by_name("set_trait")?;

    let ln = TcpListener::bind("127.0.0.1:0")?;
    setsockopt(&ln, SoAttachBpf, &prog.as_fd().as_raw_fd())?;
    setsockopt(&ln, TcpSaveSynTraits, &false)?;

    let _c = TcpStream::connect(ln.local_addr()?);
    let (p, _) = ln.accept()?;

    assert_eq!(Ok(false), getsockopt(&ln, TcpSaveSynTraits));
    assert_eq!(Ok(vec![]), getsockopt(&p, TcpSynTraits(&[42])));

    Ok(())
}

#[test]
pub fn trait_len_zero_when_absent() -> TestResult {
    let ln = TcpListener::bind("127.0.0.1:0")?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let _c = TcpStream::connect(ln.local_addr()?);
    let (p, _) = ln.accept()?;

    assert_eq!(getsockopt(&p, TcpSynTraits(&[42])), Ok(vec![42.into()]),);

    Ok(())
}

#[test]
pub fn can_read_one_trait_set_by_socket_filter() -> TestResult {
    let obj = load_bpf()?;
    let prog = obj.get_prog_by_name("set_trait")?;

    let ln = TcpListener::bind("127.0.0.1:0")?;
    setsockopt(&ln, SoAttachBpf, &prog.as_fd().as_raw_fd())?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let _c = TcpStream::connect(ln.local_addr()?);
    let (p, _) = ln.accept()?;

    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[42])),
        Ok(vec![(42, 207_u16).into()]),
    );

    Ok(())
}

#[test]
pub fn can_read_two_traits_set_by_socket_filter() -> TestResult {
    let obj = load_bpf()?;
    let prog = obj.get_prog_by_name("set_two_traits")?;

    let ln = TcpListener::bind("127.0.0.1:0")?;
    setsockopt(&ln, SoAttachBpf, &prog.as_fd().as_raw_fd())?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let _c = TcpStream::connect(ln.local_addr()?);
    let (p, _) = ln.accept()?;

    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[16, 32])),
        Ok(vec![(16, 0x1616_u16).into(), (32, 0x3232_3232_u32).into()]),
    );

    Ok(())
}

#[ignore]
#[test]
pub fn einval_on_get_for_short_buffer() -> TestResult {
    todo!()
}

#[ignore]
#[test]
pub fn einval_when_trait_len_not_pow2() -> TestResult {
    todo!()
}

#[ignore]
#[test]
pub fn can_do_sparse_read_with_one_trait_absent() -> TestResult {
    todo!()
}

#[ignore]
#[test]
pub fn saved_traits_cleared_on_disconnect() -> TestResult {
    todo!()
}

fn tcp_socket_v4() -> nix::Result<OwnedFd> {
    socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
}

#[test]
pub fn setting_empty_traits_yields_error() -> TestResult {
    let c = tcp_socket_v4()?;

    assert_eq!(
        Err(Errno::EINVAL),
        setsockopt(&c, TcpSynTraitsSet::default(), &[])
    );

    Ok(())
}

// TODO: test - short buffer on set - optlen % sizeof(struct pkt_trait) != 0

fn set_tcp_syn_traits(fd: impl AsFd, val: &[u8]) -> nix::Result<()> {
    let res = unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            libc::SOL_TCP,
            TCP_SYN_TRAITS,
            val.as_ptr().cast(),
            mem::size_of_val(val) as libc::socklen_t,
        )
    };
    nix::errno::Errno::result(res).map(drop)
}

#[test]
pub fn einval_on_set_for_short_buffer() -> TestResult {
    let c = tcp_socket_v4()?;

    const GOOD_SIZE: usize = mem::size_of::<PktTrait>();

    assert_eq!(
        Err(Errno::EINVAL),
        set_tcp_syn_traits(&c, &[0u8; GOOD_SIZE - 1])
    );
    assert_eq!(
        Err(Errno::EINVAL),
        set_tcp_syn_traits(&c, &[0u8; GOOD_SIZE + 1])
    );
    assert_eq!(
        Err(Errno::EINVAL),
        set_tcp_syn_traits(&c, &[0u8; 2 * GOOD_SIZE - 4])
    );
    assert_eq!(
        Err(Errno::EINVAL),
        set_tcp_syn_traits(&c, &[0u8; 2 * GOOD_SIZE + 4])
    );

    Ok(())
}

#[test]
pub fn can_set_one_trait() -> TestResult {
    let c = tcp_socket_v4()?;

    let traits = [(42, 0xcfcf_u16).into()];
    assert_eq!(Ok(()), setsockopt(&c, TcpSynTraitsSet::default(), &traits));

    Ok(())
}

#[test]
pub fn can_set_two_traits() -> TestResult {
    let c = tcp_socket_v4()?;

    let traits = [(0xa, 0xaaaa_u16).into(), (0xb, 0xbbbb_bbbb_u32).into()];
    setsockopt(&c, TcpSynTraitsSet::default(), &traits)?;

    Ok(())
}

#[test]
pub fn can_get_back_set_trait() -> TestResult {
    let c = tcp_socket_v4()?;

    let traits = [(42, 0xcfcf_u16).into()];
    setsockopt(&c, TcpSynTraitsSet::default(), &traits)?;

    assert_eq!(
        getsockopt(&c, TcpSynTraits(&[42])),
        Ok(vec![(42, 0xcfcf_u16).into()])
    );

    Ok(())
}

#[test]
pub fn can_send_and_recv_u16_trait() -> TestResult {
    let ln = TcpListener::bind(LOOPBACK_V4)?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let c = tcp_socket_v4()?;
    let t = [(42, 0xaaaa_u16).into()];
    setsockopt(&c, TcpSynTraitsSet::default(), &t)?;
    connect(c.as_raw_fd(), &SockaddrStorage::from(ln.local_addr()?))?;

    let (p, _) = ln.accept()?;
    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[42])),
        Ok(vec![(42, 0xaaaa_u16).into()])
    );

    Ok(())
}

#[test]
pub fn can_send_and_recv_u32_trait() -> TestResult {
    let ln = TcpListener::bind(LOOPBACK_V4)?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let c = tcp_socket_v4()?;
    let t = [(42, 0xaaaa_bbbb_u32).into()];
    setsockopt(&c, TcpSynTraitsSet::default(), &t)?;
    connect(c.as_raw_fd(), &SockaddrStorage::from(ln.local_addr()?))?;

    let (p, _) = ln.accept()?;
    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[42])),
        Ok(vec![(42, 0xaaaa_bbbb_u32).into()])
    );

    Ok(())
}

#[test]
pub fn can_send_and_recv_u64_trait() -> TestResult {
    let ln = TcpListener::bind(LOOPBACK_V4)?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let c = tcp_socket_v4()?;
    let t = [(42, 0xaaaa_bbbb_cccc_dddd_u64).into()];
    setsockopt(&c, TcpSynTraitsSet::default(), &t)?;
    connect(c.as_raw_fd(), &SockaddrStorage::from(ln.local_addr()?))?;

    let (p, _) = ln.accept()?;
    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[42])),
        Ok(vec![(42, 0xaaaa_bbbb_cccc_dddd_u64).into()])
    );

    Ok(())
}

#[test]
pub fn can_send_and_recv_many_traits() -> TestResult {
    let ln = TcpListener::bind(LOOPBACK_V4)?;
    setsockopt(&ln, TcpSaveSynTraits, &true)?;

    let c = tcp_socket_v4()?;
    let t = [
        (0xa, 0xaaaa_u16).into(),
        (0xb, 0xbbbb_bbbb_u32).into(),
        (0xc, 0xcccc_cccc_cccc_cccc_u64).into(),
    ];
    setsockopt(&c, TcpSynTraitsSet::default(), &t)?;
    connect(c.as_raw_fd(), &SockaddrStorage::from(ln.local_addr()?))?;

    let (p, _) = ln.accept()?;
    assert_eq!(
        getsockopt(&p, TcpSynTraits(&[0xa, 0xb, 0xc, 0xd])),
        Ok(vec![
            (0xa, 0xaaaa_u16).into(),
            (0xb, 0xbbbb_bbbb_u32).into(),
            (0xc, 0xcccc_cccc_cccc_cccc_u64).into(),
            (0xd).into(),
        ])
    );

    Ok(())
}

#[test]
pub fn zero_length_trait_ignored_on_set() -> TestResult {
    let c = tcp_socket_v4()?;

    assert_eq!(
        Ok(()),
        setsockopt(&c, TcpSynTraitsSet::default(), &[42.into()])
    );

    Ok(())
}

#[test]
pub fn cant_set_trait_on_listening_or_connected_socket() -> TestResult {
    let ln = TcpListener::bind(LOOPBACK_V4)?;
    let c = TcpStream::connect(ln.local_addr()?)?;

    assert_eq!(
        Err(Errno::EOPNOTSUPP),
        setsockopt(&ln, TcpSynTraitsSet::default(), &[(42, 0xcfcfu16).into()])
    );
    assert_eq!(
        Err(Errno::EOPNOTSUPP),
        setsockopt(&c, TcpSynTraitsSet::default(), &[(42, 0xcfcfu16).into()])
    );

    Ok(())
}

#[ignore]
#[test]
pub fn enospc_for_too_many_traits_on_first_set() -> TestResult {
    todo!()
}

#[ignore]
#[test]
pub fn enospc_for_too_many_traits_on_second_set() -> TestResult {
    todo!()
}

#[test]
pub fn can_construct_pkt_trait() -> TestResult {
    let _t = PktTrait {
        key: 42,
        len: 2,
        val: 0xcfcf,
        .. Default::default()
    };

    Ok(())
}
