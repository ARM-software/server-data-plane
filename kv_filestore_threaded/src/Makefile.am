bin_PROGRAMS = qdofs qdofs_debug qdofs_tester
qdofs_SOURCES = qdofs.cpp \
                acceptor.cpp \
                config.cpp \
                file_io.cpp \
                pipe.cpp \
                replicator.cpp \
                worker.cpp \
                worker_transaction.cpp \
                util.cpp
qdofs_debug_SOURCES =  qdofs.cpp \
                acceptor.cpp \
                config.cpp \
                file_io.cpp \
                pipe.cpp \
                replicator.cpp \
                worker.cpp \
                worker_transaction.cpp \
                util.cpp
qdofs_tester_SOURCES = qdofs_tester.cpp

qdofs_CXXFLAGS = $(AM_CXXFLAGS) -Wall -std=c++11
qdofs_LDADD = -ltcmalloc -lpthread

qdofs_debug_CXXFLAGS = $(AM_CXXFLAGS) -Wall -std=c++11 -DDEBUG
qdofs_debug_LDADD = -ltcmalloc -lpthread
