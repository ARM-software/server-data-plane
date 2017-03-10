bin_PROGRAMS = qdofs qdofs_debug qdofs_tester
qdofs_SOURCES = qdofs.cpp \
                config.cpp \
                objpool.cpp \
                util.cpp \
                worker.cpp \
                worker_transaction.cpp
qdofs_debug_SOURCES =  qdofs.cpp \
                config.cpp \
                objpool.cpp \
                util.cpp \
                worker.cpp \
                worker_transaction.cpp
qdofs_tester_SOURCES = qdofs_tester.cpp

qdofs_CXXFLAGS = $(AM_CXXFLAGS) -Wall -std=c++11
qdofs_LDADD = -lodp-linux -lodphelper-linux

qdofs_debug_CXXFLAGS = $(AM_CXXFLAGS) -Wall -std=c++11 -DDEBUG
qdofs_debug_LDADD = -lodp-linux -lodphelper-linux
