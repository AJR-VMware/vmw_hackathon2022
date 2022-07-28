#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

struct query_data {
    u32 pid;
    u64 timestamp;
    u64 delta;
    char query_string[200];
};

BPF_PERF_OUTPUT(events);

BPF_HASH(start_tmp, u32, struct query_data);

int probe_exec_simple_query(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    char *sql_string= (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&query.query_string, sizeof(query.query_string), sql_string);
    start_tmp.update(&pid, &query);
    events.perf_submit(ctx, &query, sizeof(query));
    return 0;
}

int probe_exec_simple_query_return(struct pt_regs *ctx)
{
    // simplifying assumption: any given PID will have only one query in flight at any given time
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data *sp;
    sp = start_tmp.lookup(&pid);
    if (sp == 0) {
        // missed tracing start
        return 0;
    }
    start_tmp.delete(&pid);

    // capture data for query return
    u64 delta = bpf_ktime_get_ns() - sp->timestamp;
    struct query_data query =  {.pid = pid, .timestamp = sp->timestamp, .delta = delta};
    __builtin_memcpy(&query.query_string, "QD Query Done(exec_simple_query)", sizeof(query.query_string));
    events.perf_submit(ctx, &query, sizeof(query));

    return 0;
}

int probe_exec_mpp_query(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data query = {};

    query.pid = pid;
    query.timestamp = bpf_ktime_get_ns();
    char *sql_string= (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&query.query_string, sizeof(query.query_string), sql_string);
    start_tmp.update(&pid, &query);
    events.perf_submit(ctx, &query, sizeof(query));
    return 0;
}

int probe_exec_mpp_query_return(struct pt_regs *ctx)
{
    // simplifying assumption: any given PID will have only one query in flight at any given time
    u32 pid = bpf_get_current_pid_tgid();
    struct query_data *sp;
    sp = start_tmp.lookup(&pid);
    if (sp == 0) {
        // missed tracing start
        return 0;
    }
    start_tmp.delete(&pid);

    // capture data for query return
    u64 delta = bpf_ktime_get_ns() - sp->timestamp;
    struct query_data query =  {.pid = pid, .timestamp = sp->timestamp, .delta = delta};
    __builtin_memcpy(&query.query_string, "QE Query Done(exec_mpp_query)", sizeof(query.query_string));
    events.perf_submit(ctx, &query, sizeof(query));
    return 0;
}
