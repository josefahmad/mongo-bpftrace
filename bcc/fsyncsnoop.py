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

# load BPF program
b = BPF(text="""

struct key_t {
    u32 tid;
};

struct val_t {
    u64 t0;
    u32 fd;
};

struct userspace_data_t {
    u32 tid;
    u32 fd;
    u64 t0;
    u64 t1;
    u64 t;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(fsync_hash, struct key_t, struct val_t);

void trace_fsync(struct pt_regs *ctx, u32 fd) {
//void trace_fsync(void *ctx) {
    u64 now = bpf_ktime_get_ns();

    struct key_t key = {};
    struct val_t val = {};
    
    key.tid = bpf_get_current_pid_tgid();
    val.t0 = now;
    val.fd = fd;

    fsync_hash.update(&key, &val);
    //events.perf_submit(ctx, &data, sizeof(data));

}

void trace_ret_fsync(struct pt_regs *ctx) {
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
    udata.t0 = val->t0;
    udata.t1 = now;
    udata.fd = val->fd;

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
b.attach_kprobe(event="do_fsync",
                fn_name="trace_fsync")

b.attach_kretprobe(event="do_fsync",
                fn_name="trace_ret_fsync")

class Data(ct.Structure):
    _fields_ = [
        ("tid", ct.c_uint),
        ("fd", ct.c_uint),
        ("t0", ct.c_ulonglong),
        ("t1", ct.c_ulonglong),
        ("t", ct.c_ulonglong),
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("do_fsync() t: " + str(event.t) + "ns")

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
