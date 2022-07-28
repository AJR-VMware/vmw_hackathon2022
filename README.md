# vmw_hackathon2022
A repo for Hong Yi and Andrew Repp to collaborate on eBPF Tracing Hackathon Idea

# Related Resources
* These were consulted during development, for ideas.
* https://www.postgresql.org/docs/current/dynamic-trace.html
* https://github.com/iovisor/bcc/blob/master/tools/dbslower.py
* https://github.com/iovisor/bcc/blob/master/tools/mysqld_qslower.py
* https://github.com/erthalion/postgres-bcc

# Currently Accomplished
* Tracing of simple and mpp queries run on local machine.
* Storing of timestamps to allow for simple latency calculations
* Tracing of network traffic between cluster nodes
* Counts of node state, to identify where time is being spent

# TODO
* Currently using simplifying assumption that each PID will only have one query in flight, to match query returns with query starts, and calculate latency.  Try to test this assumption, see if there's a more reliable way to do this (if needed).
* Try to deploy to cluster set up across multiple nodes, if possible
* Capture additional probe events of interest.

# Prepare
1. install bcc and gpdb7
2. pip3 install pyelftools

# TO RUN
* For Query Latency Tracing
    * `sudo -E python3 hackday/2022/gp_latency.py /path/to/gpdb7/bin/postgres`
* For Node State Counts
    * `sudo -E python3 hackday/2022/gp_count_nodes.py /path/to/gpdb7/bin/postgres`
* For Network Traffic
    * `sudo -E python3 hackday/2022/gp_net_query.py /path/to/gpdb7/bin/postgres`
