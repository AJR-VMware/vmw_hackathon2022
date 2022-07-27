# vmw_hackathon2022
A repo for Hong Yi and Andrew Repp to collaborate on eBPF Tracing Hackathon Idea

# Possibly Relevant Resources
* https://www.postgresql.org/docs/current/dynamic-trace.html
* https://github.com/iovisor/bcc/blob/master/tools/dbslower.py
* https://github.com/iovisor/bcc/blob/master/tools/mysqld_qslower.py
* https://github.com/erthalion/postgres-bcc

# Currently Accomplished
* Tracing of simple and exec queries run on local machine.
* Storing of timestamps to allow for simple latency calculations

# TODO
* Associate exec\_\*\_query returns with the appropriate exec\_\*\_query starts to provide more reliable latency analyses
* Try to capture and associate query text, such that the latency can be definitively associated with a specific query
* Try to deploy to cluster set up across multiple nodes, if possible
* Capture additional probe events of interest.  Notably network traffic between cluster nodes would be of interest