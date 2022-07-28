from bcc import BPF
from time import sleep
import signal
from elftools.elf.elffile import ELFFile

import argparse

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
        default="./trace_output.log",
        help="Redirect printed trace log to desired path",
    )
    return parser.parse_args()


def attach_uprobes(bpf, args):
    binary_path = args.path
    pid = args.pid
    bpf.attach_uprobe(
        name=binary_path, sym="ExecProcNodeGPDB", fn_name="count", pid=pid
    )


def flush_to_log(logpath):
    with open(logpath, "w") as fp:
        for event in EVENT_LOG_BUFFER:
            fp.write(event + "\n")


def start_trace(args):
    print("Attaching BPF Module to Greenplum Node")
    bpf = BPF(src_file="gp_count_nodes.c")
    attach_uprobes(bpf, args)
    nodetag = get_enum(args.path, "NodeTag")
    # Poll perf buffer, waiting for events to capture
    interrupted = False
    while not interrupted:
        try:
            counts = bpf.get_table("counts")
            for k, v in counts.items_lookup_and_delete_batch():
                print(nodetag[k.node], v)
        except KeyboardInterrupt:
            interrupted = True
            # trap sigint to allow program time to tidy up
            signal.signal(signal.SIGINT, lambda: None)
            print("\nDetaching from Greenplum node\n")
        sleep(1)
    flush_to_log(args.output)


if __name__ == "__main__":
    args = parse_args()
    start_trace(args)
