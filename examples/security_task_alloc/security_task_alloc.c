// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common.h"
#include <sys/types.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16

struct event {
	pid_t pid;
	pid_t pgid; /* group ID */
	char comm[COMM_LEN];
};
struct event *unused_event __attribute__((unused));

struct task_struct;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("lsm/security_task_alloc")
int BPF_PROG(security_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret) {
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = (id & 0xFFFFFFFF00000000) >> 32;
	u32 pid  = id & 0x00000000FFFFFFFF;

	e->pid  = pid;
	e->pgid = tgid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
