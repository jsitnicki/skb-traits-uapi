#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	(void)ctx;

	return XDP_PASS;
}

const char _license[] SEC("license") = "GPL";
