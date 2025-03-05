set shell := ["bash", "-uc"]

# Find freshest executable
test_prog := `find target/debug/deps/ -executable -name 'run-*' | xargs ls -1t | head -1`

alias b := build
alias t := test

default: test

attach:
    ip link set dev lo \
    xdpgeneric object {{ justfile_directory() }}/tests/bpf/xdp_pass.bpf.o section xdp

build:
    make -C tests/bpf set_trait.bpf.o
    cargo test --no-run

test TEST='':
    tests/setup-lo.sh || true
    {{ test_prog }} --color=always --test-threads=1 {{ TEST }}
