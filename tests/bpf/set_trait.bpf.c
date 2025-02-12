#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

int bpf_skb_trait_set(const struct __sk_buff *skb, __u64 key,
		      const void *val, __u64 val__sz,
		      __u64 flags) __ksym __weak;

SEC("socket")
int set_trait(struct __sk_buff *skb)
{
	int err = bpf_skb_trait_set(skb, 42, &(__u16){ 207 }, sizeof(__u16), 0);
	if (err)
		bpf_printk("bpf_skb_trait_set: errno %d\n", err);

	return skb->len;
}

SEC("socket")
int set_two_traits(struct __sk_buff *skb)
{
	int err;

	err = bpf_skb_trait_set(skb, 16, &(__u16){ 0x1616 }, sizeof(__u16), 0);
	if (err)
		bpf_printk("bpf_skb_trait_set #1: errno %d\n", err);

	err = bpf_skb_trait_set(skb, 32, &(__u32){ 0x32323232 }, sizeof(__u32), 0);
	if (err)
		bpf_printk("bpf_skb_trait_set #2: errno %d\n", err);

	return skb->len;
}

const char _license[] SEC("license") = "GPL";
