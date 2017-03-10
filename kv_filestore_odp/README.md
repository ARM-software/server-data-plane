Quick and Dirty ODP File Server
===============================

This is a test app meant to mimic roughly a Ceph OSD.  It creates
and serves files to a client app that is also contained in this directory.
This application uses ODP linux-generic-server as its IO and event service
library.  It can be modified to use dpdk-ofp-server with minimal effort but
that is currently not supported.

Replication
-----------

Replication is handled by giving each file server a list of replica servers
to talk to.  None to N can be specified.  This means one can setup something
like a ceph cluster with this if we assume the Ceph CRUSH map never changes,
and we statically put together which servers talk to which a priori.

Building
--------

    ./bootstrap
    ./configure
    ./make

You need to have odp-server installed on your system for this to work.

After building two executables will be built in the src/ directory: qdofs and
qdofs_tester.

Running
-------

For benchmarking with qdofs, it is recommended to run with 0 - N replicas, and
to specify the file storage onto a RAMDisk if your disk setup is not high
performance.

To set up a cluster of 3 disk daemons, issue the following commands on
different terminals:

    ./qdofs 2000 2001 localhost:2003 localhost:2005 -c 0xf -d store1/ -t 8
    ./qdofs 2002 2003 localhost:2001 localhost:2005 -c 0xf0 -d store2/ -t 8
    ./qdofs 2004 2005 localhost:2001 localhost:2003 -c 0xf00 -d store3/ -t 8

To test the cluster, you can unit test it with the qdofs_tester by issuing the
following command: 

    ./qdofs_tester localhost 2000 1024

It can also be performance tested using the supplied modified mutilate tester
in the server-data-plane project repository.

Known Issues
============

No known issues are present for this benchmark code.  If any are found, please
submit them to the github issue tracker for the server-data-plane repository.
