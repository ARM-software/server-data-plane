Quick and Dirty Threaded File Server
====================================

This is a test app meant to mimic roughly a Ceph OSD.  It creates
and serves files to a client app that is also contained in this directory.
This application is a mirror of the kv_filestore_odp application but written
using a multi-threaded, concurrent sequential processes approach in a similar
vein to the most recent versions of Ceph.  It creates many threads to handle
asynchronous IO.  It is meant to allow people to test and investigate the pros
and cons of threaded applications versus event based applications written with
ODP because the two workloads are identical in functionality and relative code
size.

Additionally this application is written more like a modern C++ application
compared to the ODP version that is written as a hybrid C++/C application.
This application heavily utilizes the STL and C++ 11/14 features such as move
semantics to arrive at an efficient solution.  

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

This version of the workload has some issues with replication dead-locking
with more than one replica server.  This issue has not been fully debugged, if
someone solves it, please submit a pull request to the server-data-plane
repository.

If any additional issues are found, please submit them to the github issue
tracker for the server-data-plane repository.
