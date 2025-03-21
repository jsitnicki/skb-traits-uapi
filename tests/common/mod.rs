use libbpf_rs::{Object, ObjectBuilder, Program};
use nix::sys::socket::SockaddrLike;
use std::error::Error;
use std::os::fd::AsRawFd;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

#[allow(dead_code)]
pub(crate) fn load_bpf() -> Result<Object, Box<dyn Error>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/bpf/set_trait.bpf.o");
    let obj = ObjectBuilder::default().open_file(path)?.load()?;

    Ok(obj)
}

#[allow(dead_code)]
pub(crate) trait GetProg {
    fn get_prog_by_name<'obj>(&'obj self, name: &str) -> Result<Program<'obj>, Box<dyn Error>>;
}

impl GetProg for Object {
    fn get_prog_by_name<'obj>(
        self: &'obj Object,
        name: &str,
    ) -> Result<Program<'obj>, Box<dyn Error>> {
        self.progs()
            .find(|prog| prog.name() == name)
            .ok_or(Box::<dyn Error>::from("program '{name}' missing"))
    }
}

pub(crate) fn connect<F: AsRawFd, A: SockaddrLike>(fd: &F, addr: &A) -> nix::Result<()> {
    nix::sys::socket::connect(fd.as_raw_fd(), addr)
}
