# most code from postgres-bcc
# change it for greenplum
# net_per_query  Summarize network usage per query/backend.
#                For Linux, uses BCC.
#
# usage: net_per_query $PG_BIN/postgres [-d] [-p PID]

import argparse

import signal
from time import sleep

from bcc import BPF


traditional = [
    (1024 ** 5, "P"),
    (1024 ** 4, "T"),
    (1024 ** 3, "G"),
    (1024 ** 2, "M"),
    (1024 ** 1, "K"),
    (1024 ** 0, "B"),
]


def size(size_in_bytes):

    for factor, suffix in traditional:
        if size_in_bytes >= factor:
            break
    amount = int(size_in_bytes / factor)
    if isinstance(suffix, tuple):
        singular, multiple = suffix
        if amount == 1:
            suffix = singular
        else:
            suffix = multiple
    return str(amount) + suffix


def get_pid_cmdline(pid):
    try:
        return open("/proc/{}/cmdline".format(pid)).read().strip()
    except FileNotFoundError:
        return "postgres: backend {}".format(pid)


def print_result(name, table):
    print(name)
    for k, v in table.items_lookup_and_delete_batch():
        if k.name == b"postgres":
            backend = k.query.decode("ascii") or get_pid_cmdline(k.pid)
            # ignore wal things
            if backend.find("walreceiver") > 0:
                continue
            if backend.find("walsender") > 0:
                continue
            print("[{}:{}] {}: {}".format(k.pid, k.namespace, backend, size(v)))


def attach(bpf, args):
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
    bpf.attach_kprobe(event="__sys_sendto", fn_name="on_send")
    bpf.attach_kprobe(event="__sys_recvfrom", fn_name="on_recv")
    bpf.attach_kprobe(event="__sys_recvfrom", fn_name="on_recv")


def run(args):
    print("Attaching...")
    bpf = BPF(src_file="gp_net_query.c")
    attach(bpf, args)
    exiting = False
    print("Listening...")
    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, lambda: None)

        if exiting:
            print()
            print("Detaching...")
            print()
            break

        print_result("Send", bpf.get_table("send"))
        print_result("Receive", bpf.get_table("recv"))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize network usage per query/backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument("-p", "--pid", type=int, default=-1, help="trace this PID only")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
