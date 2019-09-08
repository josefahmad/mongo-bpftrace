#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# syncsnoop Trace sync() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC trace & reformat. See
# examples/hello_world.py for a BCC trace with default output example.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Aug-2015   Brendan Gregg   Created this.
# 19-Feb-2016   Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import ctypes as ct
import datetime

# load BPF program
b = BPF(text="""

// https://github.com/iovisor/bcc/issues/2119
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...)
#endif

#include "linux/jbd2.h"

struct key_t {
    u32 tid;
};

struct val_t {
    u64 t0;
    u32 fd;
    int stack_id;
};

struct userspace_data_t {
    u32 tid;
    char comm[16];
    u32 fd;
    u64 t0;
    u64 t1;
    u64 t;
    int stack_id;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(fsync_hash, struct key_t, struct val_t);
BPF_STACK_TRACE(stacks, 4096);


void trace_jbd2_journal_lock_updates(struct pt_regs *ctx, journal_t *journal) {
//void trace_fsync(void *ctx) {
    u64 now = bpf_ktime_get_ns();

    struct key_t key = {};
    struct val_t val = {};
    
    key.tid = bpf_get_current_pid_tgid();
    val.t0 = now;
    val.fd = 0;
    val.stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);

    fsync_hash.update(&key, &val);
    //events.perf_submit(ctx, &data, sizeof(data));

}

void trace_ret_jbd2_journal_lock_updates(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();

    struct key_t key = {};
    key.tid = bpf_get_current_pid_tgid();

    struct val_t *val = fsync_hash.lookup(&key);
    if (val == 0) {
	// missed event
	return;
    }

    struct userspace_data_t udata = {};

    udata.tid = key.tid;
    bpf_get_current_comm(&udata.comm, sizeof(udata.comm));
    udata.t0 = val->t0;
    udata.t1 = now;
    udata.fd = val->fd;
    udata.stack_id = val->stack_id;

    if (udata.t1 < udata.t0) {
	udata.t1 = udata.t0;
    }

    udata.t = udata.t1 - udata.t0;

    // Print only fsyncs that take 1 second or longer
//    if (udata.t < 1 * 1000 * 1000 * 1000) {
//        return;
//    }

    events.perf_submit(ctx, &udata, sizeof(udata));
};
""")
b.attach_kprobe(event="jbd2_journal_lock_updates",
                fn_name="trace_jbd2_journal_lock_updates")

b.attach_kretprobe(event="jbd2_journal_lock_updates",
                fn_name="trace_ret_jbd2_journal_lock_updates")

class Data(ct.Structure):
    _fields_ = [
        ("tid", ct.c_uint),
	("comm", ct.c_char * 16),
        ("fd", ct.c_uint),
        ("t0", ct.c_ulonglong),
        ("t1", ct.c_ulonglong),
        ("t", ct.c_ulonglong),
        ("stack_id", ct.c_ulong),
    ]


stacks = b["stacks"]

def print_stack(bpf, pid, stacks, stack_id):
    for addr in stacks.walk(stack_id):
        print('\t%16s' % (bpf.sym(addr, pid, show_module=False, show_offset=False)))

# process event
def print_event(cpu, data, size):
    global b
    global stacks
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(datetime.datetime.now().isoformat() + "jbd2_journal_lock_updates() " + "comm=" + str(event.comm) +", tid=" + str(event.tid) + ", fd=" + str(event.fd) + " " + str(float(event.t)/1000/1000) + "ms")
    print_stack(b, event.tid, stacks, event.stack_id)


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
