#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100

struct key_t {
    int pid;
    u64 namespace;
    char name[TASK_COMM_LEN];
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};


BPF_HASH(send, struct key_t);
BPF_HASH(recv, struct key_t);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    struct backend *data = queries.lookup(&(key->pid));

    bpf_get_current_comm(&(key->name), sizeof(key->name));
    if (data != NULL)
        bpf_probe_read(&(key->query), QUERY_LEN, &(data->query));
}

int on_recv(struct pt_regs *ctx) {
    struct key_t key = {};
    get_key(&key);

    
    struct task_struct *t = (struct task_struct *) bpf_get_current_task();
    key.namespace = t->nsproxy->pid_ns_for_children->ns.inum;

    u64 zero = 0, *val;
    val = recv.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

    return 0;
}

int on_send(struct pt_regs *ctx) {
    struct key_t key = {};
    get_key(&key);
    
    struct task_struct *t = (struct task_struct *) bpf_get_current_task();
    key.namespace = t->nsproxy->pid_ns_for_children->ns.inum;

    u64 zero = 0, *val;
    val = send.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

    return 0;
}

void probe_exec_simple_query(struct pt_regs *ctx, const char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct backend data = {};
    data.pid = pid;
    char *sql_string= (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&data.query, sizeof(data.query), sql_string);
    queries.update(&pid, &data);
}

void probe_exec_simple_query_finish(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    queries.delete(&pid);
}


void probe_exec_mpp_query(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct backend data = {};
    data.pid = pid;
    char *sql_string= (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&data.query, sizeof(data.query), sql_string);
    queries.update(&pid, &data);
}

void probe_exec_mpp_query_finish(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    queries.delete(&pid);
}
