"""
Summarize network usage in Greenplum cluster. Log information to file.
usage: sudo -E python3 gp_net_query.py $GPDB_BIN/postgres [-p PID] [-o LOGPATH]
"""

import argparse
from datetime import datetime
import signal
from time import sleep

from bcc import BPF


def format_size(size_in_bytes):
    size_breaks = [
        (1024**5, "P"),
        (1024**4, "T"),
        (1024**3, "G"),
        (1024**2, "M"),
        (1024**1, "K"),
        (1024**0, "B"),
    ]

    for factor, suffix in size_breaks:
        if size_in_bytes >= factor:
            break
    amount = int(size_in_bytes / factor)
    return str(amount) + suffix


def get_pid_cmdline(pid):
    try:
        return open("/proc/{}/cmdline".format(pid)).read().strip()
    except FileNotFoundError:
        return "postgres: backend {}".format(pid)


def log_traffic(name, table, logpath):
    """This will print network traffict both to stdout and to indicated log file"""
    with open(logpath, "a") as fp:
        header_printed = False
        for k, v in table.items_lookup_and_delete_batch():
            if k.name == b"postgres":
                backend = k.query.decode("ascii") or get_pid_cmdline(k.pid)
                # Discard WAL traffic when logging
                if backend.find("walreceiver") > 0:
                    continue
                if backend.find("walsender") > 0:
                    continue

                if not header_printed:
                    # print send/receive traffic as blocks with header to indicate
                    now = datetime.now()
                    print(f"{name} -- {now.strftime('%Y-%m-%d %H:%M:%S')}")
                    fp.write(f"{name} -- {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    header_printed = True

                printstring = "[{}:{}] {}: {}".format(
                    k.pid, k.namespace, backend, format_size(v)
                )
                # sanitize print string
                clean_printstring = "".join(
                    [i if i.isprintable() else " " for i in printstring]
                )
                print(clean_printstring)
                fp.write(f"{clean_printstring}\n")


def attach_probes(bpf, args):
    bpf.attach_uprobe(
        name=args.path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query",
        pid=args.pid,
    )
    bpf.attach_uretprobe(
        name=args.path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_finish",
        pid=args.pid,
    )
    bpf.attach_uprobe(
        name=args.path,
        sym="exec_mpp_query",
        fn_name="probe_exec_mpp_query",
        pid=args.pid,
    )
    bpf.attach_uretprobe(
        name=args.path,
        sym="exec_mpp_query",
        fn_name="probe_exec_mpp_query_finish",
        pid=args.pid,
    )

    bpf.attach_kprobe(event="__sys_sendto", fn_name="on_send")
    bpf.attach_kprobe(event="__sys_recvfrom", fn_name="on_recv")


def start_trace(args):
    print("Attaching BPF Module to Greenplum Node")
    bpf = BPF(src_file="gp_net_query.c")
    attach_probes(bpf, args)
    interrupted = False

    print("Listening for Kernel Events on Greenplum Node")
    while not interrupted:
        try:
            sleep(1)
            log_traffic("Send", bpf.get_table("send"), args.output)
            log_traffic("Receive", bpf.get_table("recv"), args.output)
        except KeyboardInterrupt:
            interrupted = True
            # trap sigint to allow program time to tidy up
            signal.signal(signal.SIGINT, lambda: None)
            print("\nDetaching from Greenplum node\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize network usage per query/backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", type=str, help="Path to vendored PostgreSQL binary")
    parser.add_argument(
        "-p", "--pid", type=int, default=-1, help="Trace only a single, indicated PID"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./net_trace_output.log",
        help="Redirect printed trace log to desired path",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_trace(args)
