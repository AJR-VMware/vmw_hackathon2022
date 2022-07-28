"""
Summarize node behavior in Greenplum cluster. Log information to file.
usage: sudo -E python3 gp_count_nodes.py $GPDB_BIN/postgres [-p PID] [-o LOGPATH]
"""

import argparse
import signal
from time import sleep

from bcc import BPF
from elftools.elf.elffile import ELFFile

EVENT_LOG_BUFFER = []


def get_enum(filename, enum_name):
    enum = {}
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print("No dwarf info")
            return None

        dwarfinfo = elffile.get_dwarf_info()
        enum_die = find_enum(dwarfinfo, enum_name)
        if enum_die is None:
            return None
        for child in enum_die.iter_children():
            enum[child.attributes["DW_AT_const_value"].value] = child.get_full_path()
    return enum


def find_enum(dwarfinfo, enum_name):
    for compilation_unit in dwarfinfo.iter_CUs():
        for die in compilation_unit.iter_DIEs():
            try:
                if die.tag == "DW_TAG_enumeration_type":
                    if die.get_full_path() == enum_name:
                        return die
            except KeyError:
                continue
    return None


def attach_probes(bpf, args):
    binary_path = args.path
    pid = args.pid
    bpf.attach_uprobe(
        name=binary_path, sym="ExecProcNodeGPDB", fn_name="count", pid=pid
    )


def flush_to_log(logpath):
    with open(logpath, "w") as fp:
        for event in EVENT_LOG_BUFFER:
            fp.write(event + "\n")


def log_traffic(bpf, nodetag, logpath):
    with open(logpath, "a") as fp:
        counts = bpf.get_table("counts")
        for k, v in counts.items_lookup_and_delete_batch():
            printstring = f"{nodetag[k.node]} -- {v}"
            print(printstring)
            fp.write(f"{printstring}\n")


def start_trace(args):
    print("Attaching BPF Module to Greenplum Node")
    bpf = BPF(src_file="gp_count_nodes.c")
    attach_probes(bpf, args)
    nodetag = get_enum(args.path, "NodeTag")
    interrupted = False

    print("Listening for Kernel Events on Greenplum Node")
    while not interrupted:
        try:
            sleep(1)
            log_traffic(bpf, nodetag, args.output)
        except KeyboardInterrupt:
            interrupted = True
            # trap sigint to allow program time to tidy up
            signal.signal(signal.SIGINT, lambda: None)
            print("\nDetaching from Greenplum node\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace query events for Greenplum cluster",
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
        default="./node_count_trace_output.log",
        help="Redirect printed trace log to desired path",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_trace(args)
