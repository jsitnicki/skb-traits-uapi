use nix::sys::socket::{getsockopt, setsockopt};
use std::net::{TcpListener, TcpStream};

use skb_traits::{TcpSaveSyn, TcpSavedSyn};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
pub fn can_toggle_syn_saving() -> TestResult {
    let ln = TcpListener::bind("127.0.0.1:0")?;


    assert_eq!(Ok(()), setsockopt(&ln, TcpSaveSyn, &true));
    assert_eq!(Ok(true), getsockopt(&ln, TcpSaveSyn));

    Ok(())
}

#[test]
pub fn saved_syn_empty_when_not_enabled() -> TestResult {
    let ln = TcpListener::bind("127.0.0.1:0")?;
    let _c = TcpStream::connect(ln.local_addr()?);
    let (p, _) = ln.accept()?;

    assert_eq!(Ok(false), getsockopt(&ln, TcpSaveSyn));
    assert_eq!(Ok(vec![]), getsockopt(&p, TcpSavedSyn));

    Ok(())
}
