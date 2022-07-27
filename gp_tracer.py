#!/usr/bin/python3
"""
Track query start and stop time in Greenplum. Print information in log file.
usage: sudo -E python3 gp_latency.py $GPDB_BIN/postgres [-p PID] [-o LOGPATH]
"""
import argparse
import ctypes as ct
import signal

from bcc import BPF

EVENT_LOG_BUFFER = []
class Data(ct.Structure):
    _fields_ = [
        ('pid', ct.c_uint32), 
        ('timestamp', ct.c_uint64),
        ('query_string', ct.c_char * 32)
    ]

def write_event(cpu, data, size):
    casted_data = ct.cast(data, ct.POINTER(Data)).contents     
    event_string = '{pid}|{timestamp}|{query_string}'.format(
        pid=casted_data.pid, 
        timestamp=casted_data.timestamp, 
        query_string=casted_data.query_string
    )
    print(f"Probe event: {event_string}")
    EVENT_LOG_BUFFER.append(event_string)


def attach_uprobes(bpf, args):
    binary_path = args.path
    pid = args.pid

    bpf.attach_uprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_return",
        pid=pid)
    bpf.attach_uprobe(
        name=binary_path,
        sym="exec_mpp_query",
        fn_name="probe_exec_mpp_query",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="exec_mpp_query",
        fn_name="probe_exec_mpp_query_return",
        pid=pid)



def flush_to_log(logpath):
    with open(logpath, 'w') as fp:
        for event in EVENT_LOG_BUFFER:
            fp.write(event+"\n")

def start_trace(args):
    print("Attaching BPF Module to Greenplum Node")
    bpf = BPF(src_file="gp_tracer.c")
    attach_uprobes(bpf, args)
    interrupted = False

    print("Listening for Kernel Events on Greenplum Node")
    bpf['events'].open_perf_buffer(write_event)

    # Poll perf buffer, waiting for events to capture
    while not interrupted:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            interrupted = True
            # trap sigint to allow program time to tidy up
            signal.signal(signal.SIGINT, lambda: None)
            print("\nDetaching from Greenplum node\n")

    flush_to_log(args.output)



def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace query events for Greenplum cluster",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="Path to vendored PostgreSQL binary")
    parser.add_argument(
        "-p", "--pid", type=int, default=-1,
        help="Trace only a single, indicated PID"
    )
    parser.add_argument(
        "-o", "--output", type=str, default="./trace_output.log",
        help="Redirect printed trace log to desired path"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_trace(args)
