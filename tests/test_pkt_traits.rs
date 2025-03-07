mod common;

// NOTE: These files need to be in a subdir so that `cargo test` doesn't try to
// build them as individual integration test crates. Recipe documented at:
// https://zerotomastery.io/blog/complete-guide-to-testing-code-in-rust/?utm_source=pocket_shared#Integration-testing

#[path = "pkt_traits/test_tcp_syn_traits.rs"]
mod test_tcp_syn_traits;

#[path = "pkt_traits/test_udp_pkt_traits.rs"]
mod test_udp_pkt_traits;
