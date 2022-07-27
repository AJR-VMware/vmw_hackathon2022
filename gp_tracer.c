#include <linux/ptrace.h>

struct query_data {
    u32 pid;
    u64 timestamp;
    char query_string[200];
};

#define HASH_SIZE 2^14

BPF_PERF_OUTPUT(events);

void probe_exec_simple_query(struct pt_regs *ctx, char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    strcpy(query.query_string, "exec_simple_query");
    events.perf_submit(ctx, &query, sizeof(query));
    return;
}

void probe_exec_simple_query_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    strcpy(query.query_string, "exec_simple_query_return");

    events.perf_submit(ctx, &query, sizeof(query));
    return;
}

void probe_exec_mpp_query(struct pt_regs *ctx, char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    strcpy(query.query_string, "exec_mpp_query");
    events.perf_submit(ctx, &query, sizeof(query));
    return;
}

void probe_exec_mpp_query_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    strcpy(query.query_string, "exec_mpp_query_return");

    events.perf_submit(ctx, &query, sizeof(query));
    return;
}
