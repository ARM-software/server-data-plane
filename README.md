Server Data Plane
=================

The server-data-plane (SDP) project aims to develop the Linaro OpenDataPlane (ODP) project
into a general purpose library that can be used to accelerate the
performance of server applications by using key ODP features.  The server-data-plane
repository contains not only the modified ODP library but also benchmarks to
evaluate the performance and load generation applications to drive the benchmark
applications.  These are provided with the intention for academics and industry
researchers to easily evaluate the performance of the project and pursue new avenues
in high performance networking for server applications.

Repository Contents
-------------------

The server-data-plane project contains multiple sub-directories with different
software components.  A description of each directory is provided below:

1. odp-linux-generic-server
v1.11.0 of the ODP-Linux-generic library modified to support general purpose server
applications with the addition of a TCP termination via the linux networking
stack, file IO and a generalized memory allocation.
2. odp-dpdk-ofp-server
v1.11.0 of the ODP-DPDK library modified with the same general purpose
server application support as the linux-generic version.  The main difference
is that it integrates Open Fast Path (OFP) v2.0 for TCP termination and DPDK
for fastpath packet IO instead of using the Linux network stack for TCP termination.
3. memcached-odp
This is a modified version of memcached that uses ODP as its networking and
event notification library instead of libevent and POSIX sockets.  It is
compatible with either the linux-generic or dpdk-ofp versions of ODP contained
in the server-data-plane repository.
4. mutilate-memcached
Distributed load generation application used for testing memcached-odp.
5. kv_filestore_odp
This is a microbenchmark that stores Key Value pairs in a file-system.  It
supports replication to other servers and is meant to emulate the Ceph
object-store in basic functionality.  It uses ODP as its networking, file io
and event delivery layer.
6. kv_filestore_threaded
This is the sister microbenchmark to the ODP version, and instead uses
multiple threads to perform asynchronous network and file IO instead of an
event based architecture provided by ODP.  The code structure strongly
emulates the OSD software architecture of Ceph and is meant as a comparison
point to an ODP enabled application.
7. mutilate-kv_filestore
Distributed load generation application based on original mutilate code but
modified to work with the protocol defined by the kv_filestore microbenchmark.

Building and running
--------------------

Instructions on building and running the components can be found in their
respective sub-directories.

Reporting and fixing bugs
-------------------------

Bugs can be reported through the github issue tracker for the project to
notify the maintainers of issues.  Bug fixes can be submitted for review via
pull requests to the github repository.

Contact Info
------------

For all other issues not covered by this README, please contact the lead
mainainer via email at: Geoffrey.Blake@arm.com
