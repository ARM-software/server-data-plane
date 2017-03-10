/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  memcached - memory caching daemon
 *
 *       http://www.memcached.org/
 *
 *  Copyright 2003 Danga Interactive, Inc.  All rights reserved.
 *  Copyright 2017 ARM Limited, All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Anatoly Vorobey <mellon@pobox.com>
 *      Brad Fitzpatrick <brad@danga.com>
 */

/*
 * This version of memcached uses ODP for its communications library instead
 * of libevent.  To support moving over to ODP, this version of ODP only
 * supports single GETs and PUTs of the Memcached protocol for simplicity.
 */

#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>
#include <stdarg.h>

/* some POSIX systems need the following definition
 * to get mlockall flags out of sys/mman.h.  */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif
/* need this to get IOV_MAX on some platforms. */
#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <sysexits.h>
#include <stddef.h>

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__)
# define IOV_MAX 1024
#endif
#endif

/*
 * forward declarations
 */
static void drive_machine(conn *c);
//static int new_socket(struct addrinfo *ai);
//static int try_read_command(conn *c);

enum try_read_result {
    READ_DATA_RECEIVED,
    READ_NO_DATA_RECEIVED,
    READ_ERROR,            /** an error occured (on the socket) (or client closed connection) */
    READ_MEMORY_ERROR      /** failed to allocate more memory */
};

//static enum try_read_result try_read_network(conn *c);
//static enum try_read_result try_read_udp(conn *c);

//static void conn_set_state(conn *c, enum conn_states state);

/* stats */
static void stats_init(void);
//static void server_stats(ADD_STAT add_stats, conn *c);
//static void process_stat_settings(ADD_STAT add_stats, void *c);
//static void conn_to_str(const conn *c, char *buf);


/* defaults */
static void settings_init(void);

/* event handling, network IO */
static void event_handler(const int fd, const short which, void *arg);
static void conn_close(conn *c);
static void conn_init(void);
static bool update_event(conn *c, const int new_flags);
//static void complete_nread(conn *c);
//static void process_command(conn *c, char *command);
//static void write_and_free(conn *c, char *buf, int bytes);
//static int ensure_iov_space(conn *c);
//static int add_iov(conn *c, const void *buf, int len);
//static int add_msghdr(conn *c);
//static void write_bin_error(conn *c, protocol_binary_response_status err,
//                            const char *errstr, int swallow);

//static void conn_free(conn *c);

/** exported globals **/
struct stats stats;
struct settings settings;
time_t process_started;     /* when the process was started */
conn **conns;

struct slab_rebalance slab_rebal;
volatile int slab_rebalance_signal;
extern LIBEVENT_DISPATCHER_THREAD dispatcher_thread; 
odp_instance_t instance;

/** file scope variables **/
static conn *listen_conn = NULL;
static int max_fds;
static struct event_base *main_base;

enum transmit_result {
    TRANSMIT_COMPLETE,   /** All done writing. */
    TRANSMIT_INCOMPLETE, /** More data remaining to write. */
    TRANSMIT_SOFT_ERROR, /** Can't write any more right now. */
    TRANSMIT_HARD_ERROR  /** Can't write (c->state is set to conn_closing) */
};

//static enum transmit_result transmit(conn *c);

/* This reduces the latency without adding lots of extra wiring to be able to
 * notify the listener thread of when to listen again.
 * Also, the clock timer could be broken out into its own thread and we
 * can block the listener via a condition.
 */
static volatile bool allow_new_conns = true;
static struct event maxconnsevent;
static void maxconns_handler(const int fd, const short which, void *arg) {
    struct timeval t = {.tv_sec = 0, .tv_usec = 10000};

    if (fd == -42 || allow_new_conns == false) {
        /* reschedule in 10ms if we need to keep polling */
        evtimer_set(&maxconnsevent, maxconns_handler, 0);
        event_base_set(main_base, &maxconnsevent);
        evtimer_add(&maxconnsevent, &t);
    } else {
        evtimer_del(&maxconnsevent);
        accept_new_conns(true);
    }
}

#define REALTIME_MAXDELTA 60*60*24*30

/*
 * given time value that's either unix time or delta from current unix time, return
 * unix time. Use the fact that delta can't exceed one month (and real time value can't
 * be that low).
 */
static rel_time_t realtime(const time_t exptime) {
    /* no. of seconds in 30 days - largest possible delta exptime */

    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA) {
        /* if item expiration is at/before the server started, give it an
           expiration time of 1 second after the server started.
           (because 0 means don't expire).  without this, we'd
           underflow and wrap around to some large value way in the
           future, effectively making items expiring in the past
           really expiring never */
        if (exptime <= process_started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - process_started);
    } else {
        return (rel_time_t)(exptime + current_time);
    }
}

static void stats_init(void) {
    stats.curr_items = stats.total_items = stats.curr_conns = stats.total_conns = stats.conn_structs = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = stats.evictions = stats.reclaimed = 0;
    stats.touch_cmds = stats.touch_misses = stats.touch_hits = stats.rejected_conns = 0;
    stats.malloc_fails = 0;
    stats.curr_bytes = stats.listen_disabled_num = 0;
    stats.hash_power_level = stats.hash_bytes = stats.hash_is_expanding = 0;
    stats.expired_unfetched = stats.evicted_unfetched = 0;
    stats.slabs_moved = 0;
    stats.accepting_conns = true; /* assuming we start in this state. */
    stats.slab_reassign_running = false;
    stats.lru_crawler_running = false;

    /* make the time we started always be 2 seconds before we really
       did, so time(0) - time.started is never zero.  if so, things
       like 'settings.oldest_live' which act as booleans as well as
       values are now false in boolean context... */
    process_started = time(0) - ITEM_UPDATE_INTERVAL - 2;
    stats_prefix_init();
}

#if 0
static void stats_reset(void) {
    STATS_LOCK();
    stats.total_items = stats.total_conns = 0;
    stats.rejected_conns = 0;
    stats.malloc_fails = 0;
    stats.evictions = 0;
    stats.reclaimed = 0;
    stats.listen_disabled_num = 0;
    stats_prefix_clear();
    STATS_UNLOCK();
    threadlocal_stats_reset();
    item_stats_reset();
}
#endif

static void settings_init(void) {
    settings.use_cas = true;
    settings.access = 0700;
    settings.port = 11211;
    settings.udpport = 11211;
    /* By default this string should be NULL for getaddrinfo() */
    settings.inter = NULL;
    settings.maxbytes = 64 * 1024 * 1024; /* default is 64MB */
    settings.maxconns = 1024;         /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.evict_to_free = 1;       /* push old items out of cache when memory runs out */
    settings.socketpath = NULL;       /* by default, not using a unix socket */
    settings.factor = 1.25;
    settings.chunk_size = 48;         /* space for a modest key and value */
    settings.num_threads = 4;         /* N workers */
    settings.num_threads_per_udp = 0;
    settings.prefix_delimiter = ':';
    settings.detail_enabled = 0;
    settings.reqs_per_event = 20;
    settings.backlog = 1024;
    settings.binding_protocol = negotiating_prot;
    settings.item_size_max = 1024 * 1024; /* The famous 1MB upper limit. */
    settings.maxconns_fast = false;
    settings.lru_crawler = false;
    settings.lru_crawler_sleep = 100;
    settings.lru_crawler_tocrawl = 0;
    settings.hashpower_init = 0;
    settings.slab_reassign = false;
    settings.slab_automove = 0;
    settings.shutdown_command = false;
    settings.tail_repair_time = TAIL_REPAIR_TIME_DEFAULT;
    settings.flush_enabled = true;
    /** ODP Settings **/
    settings.input_pkt_size = 2048;
    settings.input_pkt_pool_size = 2048*512*64; // 64MB of input buffer by default
    settings.output_pkt_size = 2048;
    settings.output_pkt_pool_size = 2048*512*64; // 64MB of output buffer by default
    settings.num_io_threads = 0; // Number of io threads
    /******************/
}

extern pthread_mutex_t conn_lock;

/*
 * Initializes the connections array. We don't actually allocate connection
 * structures until they're needed, so as to avoid wasting memory when the
 * maximum connection count is much higher than the actual number of
 * connections.
 *
 * This does end up wasting a few pointers' worth of memory for FDs that are
 * used for things other than connections, but that's worth it in exchange for
 * being able to directly index the conns array by FD.
 */
static void conn_init(void) {
    /* We're unlikely to see an FD much higher than maxconns. */
    int next_fd = dup(1);
    int headroom = 10;      /* account for extra unexpected open FDs */
    struct rlimit rl;

    max_fds = settings.maxconns + headroom + next_fd;

    /* But if possible, get the actual highest FD we can possibly ever see. */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        max_fds = rl.rlim_max;
    } else {
        fprintf(stderr, "Failed to query maximum file descriptor; "
                        "falling back to maxconns\n");
    }

    close(next_fd);

    if ((conns = calloc(max_fds, sizeof(conn *))) == NULL) {
        fprintf(stderr, "Failed to allocate connection structures\n");
        /* This is unrecoverable so bail out early. */
        exit(1);
    }
}

#if 0
static const char *prot_text(enum protocol prot) {
    char *rv = "unknown";
    switch(prot) {
        case ascii_prot:
            rv = "ascii";
            break;
        case binary_prot:
            rv = "binary";
            break;
        case negotiating_prot:
            rv = "auto-negotiate";
            break;
    }
    return rv;
}
#endif

conn *conn_new(const int sfd, enum conn_states init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base) {
    conn *c;

    assert(sfd >= 0 && sfd < max_fds);
    c = conns[sfd];

    if (NULL == c) {
        if (!(c = (conn *)calloc(1, sizeof(conn)))) {
            STATS_LOCK();
            stats.malloc_fails++;
            STATS_UNLOCK();
            fprintf(stderr, "Failed to allocate connection object\n");
            return NULL;
        }
        MEMCACHED_CONN_CREATE(c);

        STATS_LOCK();
        stats.conn_structs++;
        STATS_UNLOCK();

        c->sfd = sfd;
        conns[sfd] = c;
    }

    c->transport = transport;
    c->protocol = settings.binding_protocol;

    /*if (transport == tcp_transport && init_state == conn_new_cmd) {
        if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
                        &c->request_addr_size)) {
            perror("getpeername");
            memset(&c->request_addr, 0, sizeof(c->request_addr));
        }
    }*/
 
    //c->authenticated = false;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        perror("event_add");
        return NULL;
    }

    STATS_LOCK();
    stats.curr_conns++;
    stats.total_conns++;
    STATS_UNLOCK();

    MEMCACHED_CONN_ALLOCATE(c->sfd);

    return c;
}

static void conn_release_items(conn *c) {
    assert(c != NULL);

    //if (c->item) {
    //    item_remove(c->item);
    //    c->item = 0;
    //}

    //while (c->ileft > 0) {
    //    item *it = *(c->icurr);
    //    assert((it->it_flags & ITEM_SLABBED) == 0);
    //    item_remove(it);
    //    c->icurr++;
    //    c->ileft--;
    //}

    //if (c->suffixleft != 0) {
    //    for (; c->suffixleft > 0; c->suffixleft--, c->suffixcurr++) {
    //        cache_free(c->thread->suffix_cache, *(c->suffixcurr));
    //    }
    //}

    //c->icurr = c->ilist;
    //c->suffixcurr = c->suffixlist;
}

static void conn_cleanup(conn *c) {
    assert(c != NULL);

    conn_release_items(c);

    //if (c->write_and_free) {
    //    free(c->write_and_free);
    //    c->write_and_free = 0;
    //}

    //if (c->sasl_conn) {
    //    assert(settings.sasl);
    //    sasl_dispose(&c->sasl_conn);
    //    c->sasl_conn = NULL;
    //}

    //if (IS_UDP(c->transport)) {
    //    conn_set_state(c, conn_read);
    //}
}

/*
 * Frees a connection.
 */
#if 0
void conn_free(conn *c) {
    if (c) {
        assert(c != NULL);
        assert(c->sfd >= 0 && c->sfd < max_fds);

        MEMCACHED_CONN_DESTROY(c);
        conns[c->sfd] = NULL;
        //if (c->hdrbuf)
        //    free(c->hdrbuf);
        //if (c->msglist)
        //    free(c->msglist);
        //if (c->rbuf)
        //    free(c->rbuf);
        //if (c->wbuf)
        //    free(c->wbuf);
        //if (c->ilist)
        //    free(c->ilist);
        //if (c->suffixlist)
        //    free(c->suffixlist);
        //if (c->iov)
        //    free(c->iov);
        free(c);
    }
}
#endif

static void conn_close(conn *c) {
    assert(c != NULL);

    /* delete the event, the socket and the conn */
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    conn_cleanup(c);

    MEMCACHED_CONN_RELEASE(c->sfd);
    //conn_set_state(c, conn_closed);
    close(c->sfd);

    pthread_mutex_lock(&conn_lock);
    allow_new_conns = true;
    pthread_mutex_unlock(&conn_lock);

    STATS_LOCK();
    stats.curr_conns--;
    STATS_UNLOCK();

    return;
}

/*
 * Shrinks a connection's buffers if they're too big.  This prevents
 * periodic large "get" requests from permanently chewing lots of server
 * memory.
 *
 * This should only be called in between requests since it can wipe output
 * buffers!
 */
#if 0
static void conn_shrink(conn *c) {
    assert(c != NULL);

    if (IS_UDP(c->transport))
        return;

    if (c->rsize > READ_BUFFER_HIGHWAT && c->rbytes < DATA_BUFFER_SIZE) {
        char *newbuf;

        if (c->rcurr != c->rbuf)
            memmove(c->rbuf, c->rcurr, (size_t)c->rbytes);

        newbuf = (char *)realloc((void *)c->rbuf, DATA_BUFFER_SIZE);

        if (newbuf) {
            c->rbuf = newbuf;
            c->rsize = DATA_BUFFER_SIZE;
        }
        /* TODO check other branch... */
        c->rcurr = c->rbuf;
    }

    if (c->isize > ITEM_LIST_HIGHWAT) {
        item **newbuf = (item**) realloc((void *)c->ilist, ITEM_LIST_INITIAL * sizeof(c->ilist[0]));
        if (newbuf) {
            c->ilist = newbuf;
            c->isize = ITEM_LIST_INITIAL;
        }
    /* TODO check error condition? */
    }

    if (c->msgsize > MSG_LIST_HIGHWAT) {
        struct msghdr *newbuf = (struct msghdr *) realloc((void *)c->msglist, MSG_LIST_INITIAL * sizeof(c->msglist[0]));
        if (newbuf) {
            c->msglist = newbuf;
            c->msgsize = MSG_LIST_INITIAL;
        }
    /* TODO check error condition? */
    }

    if (c->iovsize > IOV_LIST_HIGHWAT) {
        struct iovec *newbuf = (struct iovec *) realloc((void *)c->iov, IOV_LIST_INITIAL * sizeof(c->iov[0]));
        if (newbuf) {
            c->iov = newbuf;
            c->iovsize = IOV_LIST_INITIAL;
        }
    /* TODO check return value */
    }
}
#endif

/**
 * Convert a state name to a human readable form.
 */
#if 0
static const char *state_text(enum conn_states state) {
    const char* const statenames[] = { "conn_listening",
                                       "conn_new_cmd",
                                       "conn_waiting",
                                       "conn_read",
                                       "conn_parse_cmd",
                                       "conn_write",
                                       "conn_nread",
                                       "conn_swallow",
                                       "conn_closing",
                                       "conn_mwrite",
                                       "conn_closed" };
    return statenames[state];
}
#endif

/*
 * Outputs a protocol-specific "out of memory" error. For ASCII clients,
 * this is equivalent to out_string().
 */
#if 0
static void out_of_memory(conn *c, char *ascii_error) {
    const static char error_prefix[] = "SERVER_ERROR ";
    const static int error_prefix_len = sizeof(error_prefix) - 1;

    if (c->protocol == binary_prot) {
        /* Strip off the generic error prefix; it's irrelevant in binary */
        if (!strncmp(ascii_error, error_prefix, error_prefix_len)) {
            ascii_error += error_prefix_len;
        }
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, ascii_error, 0);
    } else {
        out_string(c, ascii_error);
    }
}
#endif

static void odp_add_bin_header(protocol_binary_response_header *header, uint8_t cmd, 
                               uint16_t err, uint8_t ext_len, uint16_t key_len,
                               uint32_t body_len, uint32_t opaque, uint64_t cas)
{
    header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
    header->response.opcode = cmd;
    header->response.keylen = (uint16_t)htons(key_len);

    header->response.extlen = (uint8_t)ext_len;
    header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
    header->response.status = (uint16_t)htons(err);

    header->response.bodylen = htonl(body_len);
    header->response.opaque = opaque;
    header->response.cas = htonll(cas);

    if (settings.verbose > 1) {
        int ii;
        fprintf(stderr, "> Writing bin response:");
        for (ii = 0; ii < sizeof(header->bytes); ++ii) {
            //if (ii % 4 == 0) {
            //    fprintf(stderr, "\n>%d  ", c->sfd);
            //}
            fprintf(stderr, " 0x%02x", header->bytes[ii]);
        }
        fprintf(stderr, "\n");
    }
}

#if 0
static void complete_incr_bin(conn *c) {
    item *it;
    char *key;
    size_t nkey;
    /* Weird magic in add_delta forces me to pad here */
    char tmpbuf[INCR_MAX_STORAGE_LEN];
    uint64_t cas = 0;

    protocol_binary_response_incr* rsp = (protocol_binary_response_incr*)c->wbuf;
    protocol_binary_request_incr* req = binary_get_request(c);

    assert(c != NULL);
    assert(c->wsize >= sizeof(*rsp));

    /* fix byteorder in the request */
    req->message.body.delta = ntohll(req->message.body.delta);
    req->message.body.initial = ntohll(req->message.body.initial);
    req->message.body.expiration = ntohl(req->message.body.expiration);
    key = binary_get_key(c);
    nkey = c->binary_header.request.keylen;

    if (settings.verbose > 1) {
        int i;
        fprintf(stderr, "incr ");

        for (i = 0; i < nkey; i++) {
            fprintf(stderr, "%c", key[i]);
        }
        fprintf(stderr, " %lld, %llu, %d\n",
                (long long)req->message.body.delta,
                (long long)req->message.body.initial,
                req->message.body.expiration);
    }

    if (c->binary_header.request.cas != 0) {
        cas = c->binary_header.request.cas;
    }
    switch(add_delta(c, key, nkey, c->cmd == PROTOCOL_BINARY_CMD_INCREMENT,
                     req->message.body.delta, tmpbuf,
                     &cas)) {
    case OK:
        rsp->message.body.value = htonll(strtoull(tmpbuf, NULL, 10));
        if (cas) {
            c->cas = cas;
        }
        write_bin_response(c, &rsp->message.body, 0, 0,
                           sizeof(rsp->message.body.value));
        break;
    case NON_NUMERIC:
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL, NULL, 0);
        break;
    case EOM:
        out_of_memory(c, "SERVER_ERROR Out of memory incrementing value");
        break;
    case DELTA_ITEM_NOT_FOUND:
        if (req->message.body.expiration != 0xffffffff) {
            /* Save some room for the response */
            rsp->message.body.value = htonll(req->message.body.initial);

            snprintf(tmpbuf, INCR_MAX_STORAGE_LEN, "%llu",
                (unsigned long long)req->message.body.initial);
            int res = strlen(tmpbuf);
            it = item_alloc(key, nkey, 0, realtime(req->message.body.expiration),
                            res + 2);

            if (it != NULL) {
                memcpy(ITEM_data(it), tmpbuf, res);
                memcpy(ITEM_data(it) + res, "\r\n", 2);

                if (store_item(it, NREAD_ADD, c)) {
                    c->cas = ITEM_get_cas(it);
                    write_bin_response(c, &rsp->message.body, 0, 0, sizeof(rsp->message.body.value));
                } else {
                    write_bin_error(c, PROTOCOL_BINARY_RESPONSE_NOT_STORED,
                                    NULL, 0);
                }
                item_remove(it);         /* release our reference */
            } else {
                out_of_memory(c,
                        "SERVER_ERROR Out of memory allocating new item");
            }
        } else {
            pthread_mutex_lock(&c->thread->stats.mutex);
            if (c->cmd == PROTOCOL_BINARY_CMD_INCREMENT) {
                c->thread->stats.incr_misses++;
            } else {
                c->thread->stats.decr_misses++;
            }
            pthread_mutex_unlock(&c->thread->stats.mutex);

            write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
        }
        break;
    case DELTA_ITEM_CAS_MISMATCH:
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, NULL, 0);
        break;
    }
}

static void complete_update_bin(conn *c) {
    protocol_binary_response_status eno = PROTOCOL_BINARY_RESPONSE_EINVAL;
    enum store_item_type ret = NOT_STORED;
    assert(c != NULL);

    item *it = c->item;

    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.slab_stats[it->slabs_clsid].set_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

    /* We don't actually receive the trailing two characters in the bin
     * protocol, so we're going to just set them here */
    *(ITEM_data(it) + it->nbytes - 2) = '\r';
    *(ITEM_data(it) + it->nbytes - 1) = '\n';

    ret = store_item(it, c->cmd, c);

#ifdef ENABLE_DTRACE
    uint64_t cas = ITEM_get_cas(it);
    switch (c->cmd) {
    case NREAD_ADD:
        MEMCACHED_COMMAND_ADD(c->sfd, ITEM_key(it), it->nkey,
                              (ret == STORED) ? it->nbytes : -1, cas);
        break;
    case NREAD_REPLACE:
        MEMCACHED_COMMAND_REPLACE(c->sfd, ITEM_key(it), it->nkey,
                                  (ret == STORED) ? it->nbytes : -1, cas);
        break;
    case NREAD_APPEND:
        MEMCACHED_COMMAND_APPEND(c->sfd, ITEM_key(it), it->nkey,
                                 (ret == STORED) ? it->nbytes : -1, cas);
        break;
    case NREAD_PREPEND:
        MEMCACHED_COMMAND_PREPEND(c->sfd, ITEM_key(it), it->nkey,
                                 (ret == STORED) ? it->nbytes : -1, cas);
        break;
    case NREAD_SET:
        MEMCACHED_COMMAND_SET(c->sfd, ITEM_key(it), it->nkey,
                              (ret == STORED) ? it->nbytes : -1, cas);
        break;
    }
#endif

    switch (ret) {
    case STORED:
        /* Stored */
        write_bin_response(c, NULL, 0, 0, 0);
        break;
    case EXISTS:
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, NULL, 0);
        break;
    case NOT_FOUND:
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
        break;
    case NOT_STORED:
        if (c->cmd == NREAD_ADD) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        } else if(c->cmd == NREAD_REPLACE) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        } else {
            eno = PROTOCOL_BINARY_RESPONSE_NOT_STORED;
        }
        write_bin_error(c, eno, NULL, 0);
    }

    item_remove(c->item);       /* release the c->item reference */
    c->item = 0;
}
#endif

static odp_packet_t odp_bin_do_set(ODP_THREAD *me, uint8_t cmd,
                                   protocol_binary_request_header *req,
                                   odp_packet_t pkt, odp_pool_t pool)
{
    uint8_t key[KEY_MAX_LENGTH];
    int nkey;
    int vlen;
    item *it;
    protocol_binary_request_set* sreq = (protocol_binary_request_set*)req;
    protocol_binary_response_set *srsp;
    protocol_binary_response_status eno = PROTOCOL_BINARY_RESPONSE_EINVAL;
    enum store_item_type ret = NOT_STORED;
    odp_packet_t out_buf = ODP_PACKET_INVALID;
    uint8_t ncmd;
    nkey = sreq->message.header.request.keylen;
    odp_packet_copy_to_mem(pkt, sizeof(protocol_binary_request_set), nkey, key);    

    /* fix byteorder in the request */
    sreq->message.body.flags = ntohl(sreq->message.body.flags);
    sreq->message.body.expiration = ntohl(sreq->message.body.expiration);

    vlen = sreq->message.header.request.bodylen - (nkey + sreq->message.header.request.extlen);

    if (settings.verbose > 1) {
        int ii;
        if (cmd == PROTOCOL_BINARY_CMD_ADD) {
            fprintf(stderr, "<%d ADD ", _odp_typeval(odp_sockio_get_input(pkt)));
        } else if (cmd == PROTOCOL_BINARY_CMD_SET) {
            fprintf(stderr, "<%d SET ", _odp_typeval(odp_sockio_get_input(pkt)));
        } else {
            fprintf(stderr, "<%d REPLACE ", _odp_typeval(odp_sockio_get_input(pkt)));
        }
        for (ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", key[ii]);
        }

        fprintf(stderr, " Value len is %d", vlen);
        fprintf(stderr, "\n");
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set((char*)key, nkey);
    }

    it = item_alloc((char*)key, nkey, sreq->message.body.flags,
            realtime(sreq->message.body.expiration), vlen+2);
    
    // Setup output buffer
    out_buf = odp_packet_alloc(pool, sizeof(protocol_binary_response_set));
    if (out_buf == ODP_PACKET_INVALID) {
        printf("Failed to allocate an odp buffer\n");
	if (it) item_remove(it);
        return ODP_PACKET_INVALID;
    }
    //odp_packet_set_len(out_buf, sizeof(protocol_binary_response_set));
    srsp = (protocol_binary_response_set*)odp_packet_data(out_buf);

    if (it == 0) {
        if (! item_size_ok(nkey, sreq->message.body.flags, vlen + 2)) {
            // Create an error pkt here to return
            odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, PROTOCOL_BINARY_RESPONSE_E2BIG, 
                               0, 0, 0,
                               sreq->message.header.request.opaque, sreq->message.header.request.cas);
        } else {
            printf("SERVER_ERROR Out of memory allocating item\n");
            odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, PROTOCOL_BINARY_RESPONSE_ENOMEM, 
                               0, 0, 0,
                               sreq->message.header.request.opaque, sreq->message.header.request.cas);
        }

        /* Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET. Anywhere else too? */
        if (cmd == PROTOCOL_BINARY_CMD_SET) {
            it = item_get((char*)key, nkey);
            if (it) {
                item_unlink(it);
                item_remove(it);
            }
        }

        return out_buf;
    }

    ITEM_set_cas(it, sreq->message.header.request.cas);
    // Copy data payload into the item we successfully allocated
    odp_packet_copy_to_mem(pkt, sizeof(protocol_binary_request_set)+nkey,
                            vlen, (uint8_t*)ITEM_data(it));

    switch (cmd) {
        case PROTOCOL_BINARY_CMD_ADD:
            ncmd = NREAD_ADD;
            break;
        case PROTOCOL_BINARY_CMD_SET:
            ncmd = NREAD_SET;
            break;
        case PROTOCOL_BINARY_CMD_REPLACE:
            ncmd = NREAD_REPLACE;
            break;
        default:
            assert(0);
    }

    if (ITEM_get_cas(it) != 0) {
        ncmd = NREAD_CAS;
    }

    pthread_mutex_lock(&me->stats.mutex);
    me->stats.slab_stats[it->slabs_clsid].set_cmds++;
    pthread_mutex_unlock(&me->stats.mutex);

    /* We don't actually receive the trailing two characters in the bin
     * protocol, so we're going to just set them here */
    *(ITEM_data(it) + it->nbytes - 2) = '\r';
    *(ITEM_data(it) + it->nbytes - 1) = '\n';

    ret = store_item(it, ncmd, me);

    switch (ret) {
    case STORED:
        /* Stored */
        odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, PROTOCOL_BINARY_RESPONSE_SUCCESS, 
                           0, 0, 0,
                           sreq->message.header.request.opaque, ITEM_get_cas(it));
        break;
    case EXISTS:
        odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 
                           0, 0, 0,
                           sreq->message.header.request.opaque, sreq->message.header.request.cas);
        break;
    case NOT_FOUND:
        odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 
                           0, 0, 0,
                           sreq->message.header.request.opaque, sreq->message.header.request.cas);
        break;
    case NOT_STORED:
        if (ncmd == NREAD_ADD) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        } else if(ncmd == NREAD_REPLACE) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        } else {
            eno = PROTOCOL_BINARY_RESPONSE_NOT_STORED;
        }
        odp_add_bin_header((protocol_binary_response_header*)srsp, cmd, eno, 
                           0, 0, 0,
                           sreq->message.header.request.opaque, sreq->message.header.request.cas);
    }

    // Release our reference to item *it
    item_remove(it);
    it = 0;

    return out_buf;
}

static odp_packet_t odp_bin_do_get_touch(ODP_THREAD *me, uint8_t cmd, 
                                         protocol_binary_request_header *req, 
                                         odp_packet_t pkt, odp_pool_t pool) 
{
    item *it;

    protocol_binary_response_get* rsp;
    odp_packet_t out_buf = ODP_PACKET_INVALID;

    uint8_t key[KEY_MAX_LENGTH]; //= binary_get_key(c);
    size_t nkey = req->request.keylen;
    if (nkey > KEY_MAX_LENGTH) {
        perror("Got a key larger than max size!\n");
        return ODP_PACKET_INVALID;
    }    

    int key_offset = sizeof(protocol_binary_request_header);
    uint32_t extlen;
    uint32_t totallen;

    switch (cmd) {
        case PROTOCOL_BINARY_CMD_TOUCH:
        case PROTOCOL_BINARY_CMD_GAT:
        case PROTOCOL_BINARY_CMD_GATK:
            key_offset = sizeof(protocol_binary_request_touch);
            break;
        default:
            break;
    }
    // Doing a copy here...may be able to extract directly in some cases...
    odp_packet_copy_to_mem(pkt, key_offset, nkey, key);

    int should_touch = (cmd == PROTOCOL_BINARY_CMD_TOUCH ||
                        cmd == PROTOCOL_BINARY_CMD_GAT ||
                        cmd == PROTOCOL_BINARY_CMD_GATK);
    int should_return_key = (cmd == PROTOCOL_BINARY_CMD_GETK ||
                             cmd == PROTOCOL_BINARY_CMD_GATK);
    int should_return_value = (cmd != PROTOCOL_BINARY_CMD_TOUCH);

    if (settings.verbose > 1) {
        fprintf(stderr, "< %s ", should_touch ? "TOUCH" : "GET");
        fwrite(key, 1, nkey, stderr);
        fputc('\n', stderr);
    }

    if (should_touch) {
        protocol_binary_request_touch *t = (protocol_binary_request_touch*)req;
        time_t exptime = ntohl(t->message.body.expiration);

        it = item_touch((char*)key, nkey, realtime(exptime));
    } else {
        it = item_get((char*)key, nkey);
    }

    if (it) {
        /* the length has two unnecessary bytes ("\r\n") */
        uint16_t keylen = 0;
        uint32_t bodylen = sizeof(rsp->message.body) + (it->nbytes - 2);

        if (cmd == PROTOCOL_BINARY_CMD_TOUCH) {
            bodylen -= it->nbytes - 2;
        } else if (should_return_key) {
            bodylen += nkey;
            keylen = nkey;
        }

        // Setup the buffer
        out_buf = odp_packet_alloc(pool, sizeof(protocol_binary_response_header) + bodylen);
        //printf("Allocate buffer of %ldB\n", (sizeof(protocol_binary_response_header) + bodylen));
        if (out_buf == ODP_PACKET_INVALID) {
            item_remove(it);
            return ODP_PACKET_INVALID;
        }
        //odp_packet_set_len(out_buf, sizeof(protocol_binary_response_header) + bodylen);
        rsp = (protocol_binary_response_get*)odp_packet_data(out_buf);

        item_update(it);
        pthread_mutex_lock(&me->stats.mutex);
        if (should_touch) {
            me->stats.touch_cmds++;
            me->stats.slab_stats[it->slabs_clsid].touch_hits++;
        } else {
            me->stats.get_cmds++;
            me->stats.slab_stats[it->slabs_clsid].get_hits++;
        }
        pthread_mutex_unlock(&me->stats.mutex);

        extlen = sizeof(rsp->message.body);
        odp_add_bin_header((protocol_binary_response_header*)rsp, cmd, 0, extlen, keylen,
                           bodylen, req->request.opaque, req->request.cas);
        rsp->message.header.response.cas = htonll(ITEM_get_cas(it));

        // add the flags
        rsp->message.body.flags = htonl(strtoul(ITEM_suffix(it), NULL, 10));

        // Fill the response packets
        if (should_return_key && should_return_value) {
            odp_packet_copy_from_mem(out_buf, sizeof(rsp->bytes),
                                   keylen, (uint8_t*)ITEM_key(it));
            odp_packet_copy_from_mem(out_buf, sizeof(rsp->bytes)+nkey, 
                               it->nbytes -2, (uint8_t*)ITEM_data(it));
        } else if (should_return_value) {
            /* Add the data minus the CRLF */
            odp_packet_copy_from_mem(out_buf, sizeof(rsp->bytes), 
                               it->nbytes - 2, (uint8_t*)ITEM_data(it));
        }

        // release reference to the item* it
        item_remove(it);
        it = 0;
    } else {
        protocol_binary_response_header *hdr;
        pthread_mutex_lock(&me->stats.mutex);
        if (should_touch) {
            me->stats.touch_cmds++;
            me->stats.touch_misses++;
        } else {
            me->stats.get_cmds++;
            me->stats.get_misses++;
        }
        pthread_mutex_unlock(&me->stats.mutex);
        

        // no support for corking for now
        //if (noreply) {
        if (should_return_key) {
            out_buf = odp_packet_alloc(pool, sizeof(protocol_binary_response_header) + nkey);
            //odp_packet_set_len(out_buf, sizeof(protocol_binary_response_header) + nkey);
            hdr = (protocol_binary_response_header*)odp_packet_data(out_buf);
            extlen = 0;
            totallen = extlen+nkey;

            odp_add_bin_header(hdr, cmd, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 
                               extlen, nkey, totallen,
                               req->request.opaque, req->request.cas);
            odp_packet_copy_from_mem(out_buf, sizeof(protocol_binary_response_header), nkey, key);
        } else {
            out_buf = odp_packet_alloc(pool, sizeof(protocol_binary_response_header));
            //odp_packet_set_len(out_buf, sizeof(protocol_binary_response_header));
            hdr = (protocol_binary_response_header*)odp_packet_data(out_buf);
            extlen = 0;
            totallen = extlen;

            odp_add_bin_header(hdr, cmd, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,
                               extlen, 0, totallen,
                               req->request.opaque, req->request.cas);
        }
    }

    if (settings.detail_enabled) {
        stats_prefix_record_get((char*)key, nkey, NULL != it);
    }

    return out_buf;
}

#if 0
static void append_bin_stats(const char *key, const uint16_t klen,
                             const char *val, const uint32_t vlen,
                             conn *c) {
    char *buf = c->stats.buffer + c->stats.offset;
    uint32_t bodylen = klen + vlen;
    protocol_binary_response_header header = {
        .response.magic = (uint8_t)PROTOCOL_BINARY_RES,
        .response.opcode = PROTOCOL_BINARY_CMD_STAT,
        .response.keylen = (uint16_t)htons(klen),
        .response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES,
        .response.bodylen = htonl(bodylen),
        .response.opaque = c->opaque
    };

    memcpy(buf, header.bytes, sizeof(header.response));
    buf += sizeof(header.response);

    if (klen > 0) {
        memcpy(buf, key, klen);
        buf += klen;

        if (vlen > 0) {
            memcpy(buf, val, vlen);
        }
    }

    c->stats.offset += sizeof(header.response) + bodylen;
}

static bool grow_stats_buf(conn *c, size_t needed) {
    size_t nsize = c->stats.size;
    size_t available = nsize - c->stats.offset;
    bool rv = true;

    /* Special case: No buffer -- need to allocate fresh */
    if (c->stats.buffer == NULL) {
        nsize = 1024;
        available = c->stats.size = c->stats.offset = 0;
    }

    while (needed > available) {
        assert(nsize > 0);
        nsize = nsize << 1;
        available = nsize - c->stats.offset;
    }

    if (nsize != c->stats.size) {
        char *ptr = realloc(c->stats.buffer, nsize);
        if (ptr) {
            c->stats.buffer = ptr;
            c->stats.size = nsize;
        } else {
            STATS_LOCK();
            stats.malloc_fails++;
            STATS_UNLOCK();
            rv = false;
        }
    }

    return rv;
}

static void append_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie)
{
    /* value without a key is invalid */
    if (klen == 0 && vlen > 0) {
        return ;
    }

    conn *c = (conn*)cookie;

    if (c->protocol == binary_prot) {
        size_t needed = vlen + klen + sizeof(protocol_binary_response_header);
        //if (!grow_stats_buf(c, needed)) {
        //    return ;
        //}
        //append_bin_stats(key, klen, val, vlen, c);
    } else {
        size_t needed = vlen + klen + 10; // 10 == "STAT = \r\n"
        //if (!grow_stats_buf(c, needed)) {
        //    return ;
        //}
        //append_ascii_stats(key, klen, val, vlen, c);
    }

    //assert(c->stats.offset <= c->stats.size);
}

static void process_bin_stat(conn *c) {
    char *subcommand = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    if (settings.verbose > 1) {
        int ii;
        fprintf(stderr, "<%d STATS ", c->sfd);
        for (ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", subcommand[ii]);
        }
        fprintf(stderr, "\n");
    }

    if (nkey == 0) {
        /* request all statistics */
        server_stats(&append_stats, c);
        (void)get_stats(NULL, 0, &append_stats, c);
    } else if (strncmp(subcommand, "reset", 5) == 0) {
        stats_reset();
    } else if (strncmp(subcommand, "settings", 8) == 0) {
        process_stat_settings(&append_stats, c);
    } else if (strncmp(subcommand, "detail", 6) == 0) {
        char *subcmd_pos = subcommand + 6;
        if (strncmp(subcmd_pos, " dump", 5) == 0) {
            int len;
            char *dump_buf = stats_prefix_dump(&len);
            if (dump_buf == NULL || len <= 0) {
                out_of_memory(c, "SERVER_ERROR Out of memory generating stats");
                return ;
            } else {
                append_stats("detailed", strlen("detailed"), dump_buf, len, c);
                free(dump_buf);
            }
        } else if (strncmp(subcmd_pos, " on", 3) == 0) {
            settings.detail_enabled = 1;
        } else if (strncmp(subcmd_pos, " off", 4) == 0) {
            settings.detail_enabled = 0;
        } else {
            write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
            return;
        }
    } else {
        if (get_stats(subcommand, nkey, &append_stats, c)) {
            if (c->stats.buffer == NULL) {
                out_of_memory(c, "SERVER_ERROR Out of memory generating stats");
            } else {
                write_and_free(c, c->stats.buffer, c->stats.offset);
                c->stats.buffer = NULL;
            }
        } else {
            write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
        }

        return;
    }

    /* Append termination package and start the transfer */
    append_stats(NULL, 0, NULL, 0, c);
    if (c->stats.buffer == NULL) {
        out_of_memory(c, "SERVER_ERROR Out of memory preparing to send stats");
    } else {
        write_and_free(c, c->stats.buffer, c->stats.offset);
        c->stats.buffer = NULL;
    }
}

/* Just write an error message and disconnect the client */
static void handle_binary_protocol_error(conn *c) {
    write_bin_error(c, PROTOCOL_BINARY_RESPONSE_EINVAL, NULL, 0);
    if (settings.verbose) {
        fprintf(stderr, "Protocol error (opcode %02x), close connection %d\n",
                c->binary_header.request.opcode, c->sfd);
    }
    c->write_and_go = conn_closing;
}

static void init_sasl_conn(conn *c) {
    assert(c);
    /* should something else be returned? */
    if (!settings.sasl)
        return;

    c->authenticated = false;

    if (!c->sasl_conn) {
        int result=sasl_server_new("memcached",
                                   NULL,
                                   my_sasl_hostname[0] ? my_sasl_hostname : NULL,
                                   NULL, NULL,
                                   NULL, 0, &c->sasl_conn);
        if (result != SASL_OK) {
            if (settings.verbose) {
                fprintf(stderr, "Failed to initialize SASL conn.\n");
            }
            c->sasl_conn = NULL;
        }
    }
}

static void bin_list_sasl_mechs(conn *c) {
    // Guard against a disabled SASL.
    if (!settings.sasl) {
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, NULL,
                        c->binary_header.request.bodylen
                        - c->binary_header.request.keylen);
        return;
    }

    init_sasl_conn(c);
    const char *result_string = NULL;
    unsigned int string_length = 0;
    int result=sasl_listmech(c->sasl_conn, NULL,
                             "",   /* What to prepend the string with */
                             " ",  /* What to separate mechanisms with */
                             "",   /* What to append to the string */
                             &result_string, &string_length,
                             NULL);
    if (result != SASL_OK) {
        /* Perhaps there's a better error for this... */
        if (settings.verbose) {
            fprintf(stderr, "Failed to list SASL mechanisms.\n");
        }
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, NULL, 0);
        return;
    }
    write_bin_response(c, (char*)result_string, 0, 0, string_length);
}

static void process_bin_sasl_auth(conn *c) {
    // Guard for handling disabled SASL on the server.
    if (!settings.sasl) {
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, NULL,
                        c->binary_header.request.bodylen
                        - c->binary_header.request.keylen);
        return;
    }

    assert(c->binary_header.request.extlen == 0);

    int nkey = c->binary_header.request.keylen;
    int vlen = c->binary_header.request.bodylen - nkey;

    if (nkey > MAX_SASL_MECH_LEN) {
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_EINVAL, NULL, vlen);
        c->write_and_go = conn_swallow;
        return;
    }

    char *key = binary_get_key(c);
    assert(key);

    item *it = item_alloc(key, nkey, 0, 0, vlen);

    if (it == 0) {
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, NULL, vlen);
        c->write_and_go = conn_swallow;
        return;
    }

    c->item = it;
    c->ritem = ITEM_data(it);
    c->rlbytes = vlen;
    conn_set_state(c, conn_nread);
    c->substate = bin_reading_sasl_auth_data;
}


static void process_bin_complete_sasl_auth(conn *c) {
    assert(settings.sasl);
    const char *out = NULL;
    unsigned int outlen = 0;

    assert(c->item);
    init_sasl_conn(c);

    int nkey = c->binary_header.request.keylen;
    int vlen = c->binary_header.request.bodylen - nkey;

    char mech[nkey+1];
    memcpy(mech, ITEM_key((item*)c->item), nkey);
    mech[nkey] = 0x00;

    if (settings.verbose)
        fprintf(stderr, "mech:  ``%s'' with %d bytes of data\n", mech, vlen);

    const char *challenge = vlen == 0 ? NULL : ITEM_data((item*) c->item);

    int result=-1;

    switch (c->cmd) {
    case PROTOCOL_BINARY_CMD_SASL_AUTH:
        result = sasl_server_start(c->sasl_conn, mech,
                                   challenge, vlen,
                                   &out, &outlen);
        break;
    case PROTOCOL_BINARY_CMD_SASL_STEP:
        result = sasl_server_step(c->sasl_conn,
                                  challenge, vlen,
                                  &out, &outlen);
        break;
    default:
        assert(false); /* CMD should be one of the above */
        /* This code is pretty much impossible, but makes the compiler
           happier */
        if (settings.verbose) {
            fprintf(stderr, "Unhandled command %d with challenge %s\n",
                    c->cmd, challenge);
        }
        break;
    }

    item_unlink(c->item);

    if (settings.verbose) {
        fprintf(stderr, "sasl result code:  %d\n", result);
    }

    switch(result) {
    case SASL_OK:
        c->authenticated = true;
        write_bin_response(c, "Authenticated", 0, 0, strlen("Authenticated"));
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.auth_cmds++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
        break;
    case SASL_CONTINUE:
        add_bin_header(c, PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE, 0, 0, outlen);
        if(outlen > 0) {
            add_iov(c, out, outlen);
        }
        conn_set_state(c, conn_mwrite);
        c->write_and_go = conn_new_cmd;
        break;
    default:
        if (settings.verbose)
            fprintf(stderr, "Unknown sasl response:  %d\n", result);
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, NULL, 0);
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.auth_cmds++;
        c->thread->stats.auth_errors++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    }
}

static bool authenticated(conn *c) {
    assert(settings.sasl);
    bool rv = false;

    switch (c->cmd) {
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_SASL_AUTH:       /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_SASL_STEP:       /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_VERSION:         /* FALLTHROUGH */
        rv = true;
        break;
    default:
        rv = c->authenticated;
    }

    if (settings.verbose > 1) {
        fprintf(stderr, "authenticated() in cmd 0x%02x is %s\n",
                c->cmd, rv ? "true" : "false");
    }

    return rv;
}
#endif

/* ODP process binary command function */
static odp_packet_t odp_dispatch_bin_command(ODP_THREAD *me, protocol_binary_request_header *req, 
                                             odp_packet_t pkt, odp_pool_t pool)
{
    int extlen = req->request.extlen;
    int keylen = req->request.keylen;
    uint32_t bodylen = req->request.bodylen;
    uint8_t cmd = req->request.opcode;
    //bool noreply = true;
    //bool protocol_error = 0;
    odp_packet_t out_pkt = ODP_PACKET_INVALID;

    // no sasl right now
    //if (settings.sasl && !authenticated(c)) {
    //    write_bin_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, NULL, 0);
    //    c->write_and_go = conn_closing;
    //    return;
    //}

    // Merely drop the request for now
    if (keylen > KEY_MAX_LENGTH) {
        // handle_binary_protocol_error();
        return ODP_PACKET_INVALID;
    }

    // Quiet support not enabled right now
    switch(cmd) {
    case PROTOCOL_BINARY_CMD_SETQ:
        cmd = PROTOCOL_BINARY_CMD_SET;
        break;
    case PROTOCOL_BINARY_CMD_ADDQ:
        cmd = PROTOCOL_BINARY_CMD_ADD;
        break;
    case PROTOCOL_BINARY_CMD_REPLACEQ:
        cmd = PROTOCOL_BINARY_CMD_REPLACE;
        break;
    case PROTOCOL_BINARY_CMD_DELETEQ:
        cmd = PROTOCOL_BINARY_CMD_DELETE;
        break;
    case PROTOCOL_BINARY_CMD_INCREMENTQ:
        cmd = PROTOCOL_BINARY_CMD_INCREMENT;
        break;
    case PROTOCOL_BINARY_CMD_DECREMENTQ:
        cmd = PROTOCOL_BINARY_CMD_DECREMENT;
        break;
    case PROTOCOL_BINARY_CMD_QUITQ:
        cmd = PROTOCOL_BINARY_CMD_QUIT;
        break;
    case PROTOCOL_BINARY_CMD_FLUSHQ:
        cmd = PROTOCOL_BINARY_CMD_FLUSH;
        break;
    case PROTOCOL_BINARY_CMD_APPENDQ:
        cmd = PROTOCOL_BINARY_CMD_APPEND;
        break;
    case PROTOCOL_BINARY_CMD_PREPENDQ:
        cmd = PROTOCOL_BINARY_CMD_PREPEND;
        break;
    case PROTOCOL_BINARY_CMD_GETQ:
        cmd = PROTOCOL_BINARY_CMD_GET;
        break;
    case PROTOCOL_BINARY_CMD_GETKQ:
        cmd = PROTOCOL_BINARY_CMD_GETK;
        break;
    case PROTOCOL_BINARY_CMD_GATQ:
        cmd = PROTOCOL_BINARY_CMD_GAT;
        break;
    case PROTOCOL_BINARY_CMD_GATKQ:
        cmd = PROTOCOL_BINARY_CMD_GAT;
        break;
    default:
        break;
        //noreply = false;
    }

    // Support only Get/Set for now
    switch (cmd) {
        case PROTOCOL_BINARY_CMD_VERSION:
            //if (extlen == 0 && keylen == 0 && bodylen == 0) {
            //    write_bin_response(c, VERSION, 0, 0, strlen(VERSION));
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got VERSION cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_FLUSH:
            //if (keylen == 0 && bodylen == extlen && (extlen == 0 || extlen == 4)) {
            //    bin_read_key(c, bin_read_flush_exptime, extlen);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a FLUSH cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
            //if (extlen == 0 && keylen == 0 && bodylen == 0) {
            //    write_bin_response(c, NULL, 0, 0, 0);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got NOOP cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_SET: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_ADD: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_REPLACE:
            if (extlen == 8 && keylen != 0 && bodylen >= (keylen + 8)) {
                //bin_read_key(c, bin_reading_set_header, 8);
                out_pkt = odp_bin_do_set(me, cmd, req, pkt, pool);
            } else {
                printf("SET protocol error!\n");
            //    protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_GETQ:  /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GET:   /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GETKQ: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GETK:
            if (extlen == 0 && bodylen == keylen && keylen > 0) {
                //bin_read_key(c, bin_reading_get_key, 0);
                out_pkt = odp_bin_do_get_touch(me, cmd, req, pkt, pool);
            } else {
                printf("GET protocol error!\n");
                //protocol_error = 1; 
            }
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
            //if (keylen > 0 && extlen == 0 && bodylen == keylen) {
            //    bin_read_key(c, bin_reading_del_header, extlen);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a DELETE cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_INCREMENT:
        case PROTOCOL_BINARY_CMD_DECREMENT:
            //if (keylen > 0 && extlen == 20 && bodylen == (keylen + extlen)) {
            //    bin_read_key(c, bin_reading_incr_header, 20);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got an INCREMENT/DECREMENT cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_APPEND:
        case PROTOCOL_BINARY_CMD_PREPEND:
            //if (keylen > 0 && extlen == 0) {
            //    bin_read_key(c, bin_reading_set_header, 0);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a APPEND/PREPEND cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_STAT:
            //if (extlen == 0) {
            //    bin_read_key(c, bin_reading_stat, 0);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a STAT cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_QUIT:
            //if (keylen == 0 && extlen == 0 && bodylen == 0) {
            //    write_bin_response(c, NULL, 0, 0, 0);
            //    c->write_and_go = conn_closing;
            //    if (c->noreply) {
            //        conn_set_state(c, conn_closing);
            //    }
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a QUIT cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
            //if (extlen == 0 && keylen == 0 && bodylen == 0) {
            //    bin_list_sasl_mechs(c);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a SASL_LIST_MECHS cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_SASL_AUTH:
        case PROTOCOL_BINARY_CMD_SASL_STEP:
            //if (extlen == 0 && keylen != 0) {
            //    bin_read_key(c, bin_reading_sasl_auth, 0);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a SASL_AUTH/SASL_STEP cmd\n");
            break;
        case PROTOCOL_BINARY_CMD_TOUCH:
        case PROTOCOL_BINARY_CMD_GAT:
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GATK:
        case PROTOCOL_BINARY_CMD_GATKQ:
            //if (extlen == 4 && keylen != 0) {
            //    bin_read_key(c, bin_reading_touch_key, 4);
            //} else {
            //    protocol_error = 1;
            //}
            printf("Got a TOUCH/GAT/GATQ/GATK/GATKQ cmd\n");
            break;
        default:
            //write_bin_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, NULL,
            //                bodylen);
            break;
    }

    //if (protocol_error)
    //    handle_binary_protocol_error(c);
    return out_pkt;
}

#if 0
static void process_bin_append_prepend(conn *c) {
    char *key;
    int nkey;
    int vlen;
    item *it;

    assert(c != NULL);

    key = binary_get_key(c);
    nkey = c->binary_header.request.keylen;
    vlen = c->binary_header.request.bodylen - nkey;

    if (settings.verbose > 1) {
        fprintf(stderr, "Value len is %d\n", vlen);
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    it = item_alloc(key, nkey, 0, 0, vlen+2);

    if (it == 0) {
        if (! item_size_ok(nkey, 0, vlen + 2)) {
            write_bin_error(c, PROTOCOL_BINARY_RESPONSE_E2BIG, NULL, vlen);
        } else {
            out_of_memory(c, "SERVER_ERROR Out of memory allocating item");
        }
        /* swallow the data line */
        c->write_and_go = conn_swallow;
        return;
    }

    ITEM_set_cas(it, c->binary_header.request.cas);

    switch (c->cmd) {
        case PROTOCOL_BINARY_CMD_APPEND:
            c->cmd = NREAD_APPEND;
            break;
        case PROTOCOL_BINARY_CMD_PREPEND:
            c->cmd = NREAD_PREPEND;
            break;
        default:
            assert(0);
    }

    c->item = it;
    c->ritem = ITEM_data(it);
    c->rlbytes = vlen;
    conn_set_state(c, conn_nread);
    c->substate = bin_read_set_value;
}

static void process_bin_flush(conn *c) {
    time_t exptime = 0;
    protocol_binary_request_flush* req = binary_get_request(c);

    if (!settings.flush_enabled) {
      // flush_all is not allowed but we log it on stats
      write_bin_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, NULL, 0);
      return;
    }

    if (c->binary_header.request.extlen == sizeof(req->message.body)) {
        exptime = ntohl(req->message.body.expiration);
    }

    if (exptime > 0) {
        settings.oldest_live = realtime(exptime) - 1;
    } else {
        settings.oldest_live = current_time - 1;
    }
    item_flush_expired();

    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.flush_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

    write_bin_response(c, NULL, 0, 0, 0);
}

static void process_bin_delete(conn *c) {
    item *it;

    protocol_binary_request_delete* req = binary_get_request(c);

    char* key = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    assert(c != NULL);

    if (settings.verbose > 1) {
        int ii;
        fprintf(stderr, "Deleting ");
        for (ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", key[ii]);
        }
        fprintf(stderr, "\n");
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key, nkey);
    }

    it = item_get(key, nkey);
    if (it) {
        uint64_t cas = ntohll(req->message.header.request.cas);
        if (cas == 0 || cas == ITEM_get_cas(it)) {
            MEMCACHED_COMMAND_DELETE(c->sfd, ITEM_key(it), it->nkey);
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[it->slabs_clsid].delete_hits++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            item_unlink(it);
            write_bin_response(c, NULL, 0, 0, 0);
        } else {
            write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, NULL, 0);
        }
        item_remove(it);      /* release our reference */
    } else {
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, NULL, 0);
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.delete_misses++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    }
}
#endif 


/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. In threaded mode, this is protected by the cache lock.
 *
 * Returns the state of storage.
 */
enum store_item_type do_store_item(item *it, int comm, ODP_THREAD* thread, 
                                   const uint32_t hv) {
    char *key = ITEM_key(it);
    item *old_it = do_item_get(key, it->nkey, hv);
    enum store_item_type stored = NOT_STORED;

    item *new_it = NULL;
    int flags;

    if (old_it != NULL && comm == NREAD_ADD) {
        /* add only adds a nonexistent item, but promote to head of LRU */
        do_item_update(old_it);
    } else if (!old_it && (comm == NREAD_REPLACE
        || comm == NREAD_APPEND || comm == NREAD_PREPEND))
    {
        /* replace only replaces an existing value; don't store */
    } else if (comm == NREAD_CAS) {
        /* validate cas operation */
        if(old_it == NULL) {
            // LRU expired
            stored = NOT_FOUND;
            pthread_mutex_lock(&thread->stats.mutex);
            thread->stats.cas_misses++;
            pthread_mutex_unlock(&thread->stats.mutex);
        }
        else if (ITEM_get_cas(it) == ITEM_get_cas(old_it)) {
            // cas validates
            // it and old_it may belong to different classes.
            // I'm updating the stats for the one that's getting pushed out
            pthread_mutex_lock(&thread->stats.mutex);
            thread->stats.slab_stats[old_it->slabs_clsid].cas_hits++;
            pthread_mutex_unlock(&thread->stats.mutex);

            item_replace(old_it, it, hv);
            stored = STORED;
        } else {
            pthread_mutex_lock(&thread->stats.mutex);
            thread->stats.slab_stats[old_it->slabs_clsid].cas_badval++;
            pthread_mutex_unlock(&thread->stats.mutex);

            if(settings.verbose > 1) {
                fprintf(stderr, "CAS:  failure: expected %llu, got %llu\n",
                        (unsigned long long)ITEM_get_cas(old_it),
                        (unsigned long long)ITEM_get_cas(it));
            }
            stored = EXISTS;
        }
    } else {
        /*
         * Append - combine new and old record into single one. Here it's
         * atomic and thread-safe.
         */
        if (comm == NREAD_APPEND || comm == NREAD_PREPEND) {
            /*
             * Validate CAS
             */
            if (ITEM_get_cas(it) != 0) {
                // CAS much be equal
                if (ITEM_get_cas(it) != ITEM_get_cas(old_it)) {
                    stored = EXISTS;
                }
            }

            if (stored == NOT_STORED) {
                /* we have it and old_it here - alloc memory to hold both */
                /* flags was already lost - so recover them from ITEM_suffix(it) */

                flags = (int) strtol(ITEM_suffix(old_it), (char **) NULL, 10);

                new_it = do_item_alloc(key, it->nkey, flags, old_it->exptime, it->nbytes + old_it->nbytes - 2 /* CRLF */, hv);

                if (new_it == NULL) {
                    /* SERVER_ERROR out of memory */
                    if (old_it != NULL)
                        do_item_remove(old_it);

                    return NOT_STORED;
                }

                /* copy data from it and old_it to new_it */

                if (comm == NREAD_APPEND) {
                    memcpy(ITEM_data(new_it), ITEM_data(old_it), old_it->nbytes);
                    memcpy(ITEM_data(new_it) + old_it->nbytes - 2 /* CRLF */, ITEM_data(it), it->nbytes);
                } else {
                    /* NREAD_PREPEND */
                    memcpy(ITEM_data(new_it), ITEM_data(it), it->nbytes);
                    memcpy(ITEM_data(new_it) + it->nbytes - 2 /* CRLF */, ITEM_data(old_it), old_it->nbytes);
                }

                it = new_it;
            }
        }

        if (stored == NOT_STORED) {
            if (old_it != NULL)
                item_replace(old_it, it, hv);
            else
                do_item_link(it, hv);

            //*cas = ITEM_get_cas(it);

            stored = STORED;
        }
    }

    if (old_it != NULL)
        do_item_remove(old_it);         /* release our reference */
    if (new_it != NULL)
        do_item_remove(new_it);

    //if (stored == STORED) {
    //    *cas = ITEM_get_cas(it);
    //}

    return stored;
}

/* return server specific stats only */
#if 0
static void server_stats(ADD_STAT add_stats, conn *c) {
    pid_t pid = getpid();
    rel_time_t now = current_time;

    struct thread_stats thread_stats;
    threadlocal_stats_aggregate(&thread_stats);
    struct slab_stats slab_stats;
    slab_stats_aggregate(&thread_stats, &slab_stats);

#ifndef WIN32
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#endif /* !WIN32 */

    STATS_LOCK();

    APPEND_STAT("pid", "%lu", (long)pid);
    APPEND_STAT("uptime", "%u", now - ITEM_UPDATE_INTERVAL);
    APPEND_STAT("time", "%ld", now + (long)process_started);
    APPEND_STAT("version", "%s", VERSION);
    APPEND_STAT("libevent", "%s", event_get_version());
    APPEND_STAT("pointer_size", "%d", (int)(8 * sizeof(void *)));

#ifndef WIN32
    append_stat("rusage_user", add_stats, c, "%ld.%06ld",
                (long)usage.ru_utime.tv_sec,
                (long)usage.ru_utime.tv_usec);
    append_stat("rusage_system", add_stats, c, "%ld.%06ld",
                (long)usage.ru_stime.tv_sec,
                (long)usage.ru_stime.tv_usec);
#endif /* !WIN32 */

    APPEND_STAT("curr_connections", "%u", stats.curr_conns - 1);
    APPEND_STAT("total_connections", "%u", stats.total_conns);
    if (settings.maxconns_fast) {
        APPEND_STAT("rejected_connections", "%llu", (unsigned long long)stats.rejected_conns);
    }
    APPEND_STAT("connection_structures", "%u", stats.conn_structs);
    APPEND_STAT("reserved_fds", "%u", stats.reserved_fds);
    APPEND_STAT("cmd_get", "%llu", (unsigned long long)thread_stats.get_cmds);
    APPEND_STAT("cmd_set", "%llu", (unsigned long long)slab_stats.set_cmds);
    APPEND_STAT("cmd_flush", "%llu", (unsigned long long)thread_stats.flush_cmds);
    APPEND_STAT("cmd_touch", "%llu", (unsigned long long)thread_stats.touch_cmds);
    APPEND_STAT("get_hits", "%llu", (unsigned long long)slab_stats.get_hits);
    APPEND_STAT("get_misses", "%llu", (unsigned long long)thread_stats.get_misses);
    APPEND_STAT("delete_misses", "%llu", (unsigned long long)thread_stats.delete_misses);
    APPEND_STAT("delete_hits", "%llu", (unsigned long long)slab_stats.delete_hits);
    APPEND_STAT("incr_misses", "%llu", (unsigned long long)thread_stats.incr_misses);
    APPEND_STAT("incr_hits", "%llu", (unsigned long long)slab_stats.incr_hits);
    APPEND_STAT("decr_misses", "%llu", (unsigned long long)thread_stats.decr_misses);
    APPEND_STAT("decr_hits", "%llu", (unsigned long long)slab_stats.decr_hits);
    APPEND_STAT("cas_misses", "%llu", (unsigned long long)thread_stats.cas_misses);
    APPEND_STAT("cas_hits", "%llu", (unsigned long long)slab_stats.cas_hits);
    APPEND_STAT("cas_badval", "%llu", (unsigned long long)slab_stats.cas_badval);
    APPEND_STAT("touch_hits", "%llu", (unsigned long long)slab_stats.touch_hits);
    APPEND_STAT("touch_misses", "%llu", (unsigned long long)thread_stats.touch_misses);
    APPEND_STAT("auth_cmds", "%llu", (unsigned long long)thread_stats.auth_cmds);
    APPEND_STAT("auth_errors", "%llu", (unsigned long long)thread_stats.auth_errors);
    APPEND_STAT("bytes_read", "%llu", (unsigned long long)thread_stats.bytes_read);
    APPEND_STAT("bytes_written", "%llu", (unsigned long long)thread_stats.bytes_written);
    APPEND_STAT("limit_maxbytes", "%llu", (unsigned long long)settings.maxbytes);
    APPEND_STAT("accepting_conns", "%u", stats.accepting_conns);
    APPEND_STAT("listen_disabled_num", "%llu", (unsigned long long)stats.listen_disabled_num);
    APPEND_STAT("threads", "%d", settings.num_threads);
    APPEND_STAT("conn_yields", "%llu", (unsigned long long)thread_stats.conn_yields);
    APPEND_STAT("hash_power_level", "%u", stats.hash_power_level);
    APPEND_STAT("hash_bytes", "%llu", (unsigned long long)stats.hash_bytes);
    APPEND_STAT("hash_is_expanding", "%u", stats.hash_is_expanding);
    if (settings.slab_reassign) {
        APPEND_STAT("slab_reassign_running", "%u", stats.slab_reassign_running);
        APPEND_STAT("slabs_moved", "%llu", stats.slabs_moved);
    }
    if (settings.lru_crawler) {
        APPEND_STAT("lru_crawler_running", "%u", stats.lru_crawler_running);
    }
    APPEND_STAT("malloc_fails", "%llu",
                (unsigned long long)stats.malloc_fails);
    STATS_UNLOCK();
}

static void process_stat_settings(ADD_STAT add_stats, void *c) {
    assert(add_stats);
    APPEND_STAT("maxbytes", "%llu", (unsigned long long)settings.maxbytes);
    APPEND_STAT("maxconns", "%d", settings.maxconns);
    APPEND_STAT("tcpport", "%d", settings.port);
    APPEND_STAT("udpport", "%d", settings.udpport);
    APPEND_STAT("inter", "%s", settings.inter ? settings.inter : "NULL");
    APPEND_STAT("verbosity", "%d", settings.verbose);
    APPEND_STAT("oldest", "%lu", (unsigned long)settings.oldest_live);
    APPEND_STAT("evictions", "%s", settings.evict_to_free ? "on" : "off");
    APPEND_STAT("domain_socket", "%s",
                settings.socketpath ? settings.socketpath : "NULL");
    APPEND_STAT("umask", "%o", settings.access);
    APPEND_STAT("growth_factor", "%.2f", settings.factor);
    APPEND_STAT("chunk_size", "%d", settings.chunk_size);
    APPEND_STAT("num_threads", "%d", settings.num_threads);
    APPEND_STAT("num_threads_per_udp", "%d", settings.num_threads_per_udp);
    APPEND_STAT("stat_key_prefix", "%c", settings.prefix_delimiter);
    APPEND_STAT("detail_enabled", "%s",
                settings.detail_enabled ? "yes" : "no");
    APPEND_STAT("reqs_per_event", "%d", settings.reqs_per_event);
    APPEND_STAT("cas_enabled", "%s", settings.use_cas ? "yes" : "no");
    APPEND_STAT("tcp_backlog", "%d", settings.backlog);
    APPEND_STAT("binding_protocol", "%s",
                prot_text(settings.binding_protocol));
    APPEND_STAT("auth_enabled_sasl", "%s", settings.sasl ? "yes" : "no");
    APPEND_STAT("item_size_max", "%d", settings.item_size_max);
    APPEND_STAT("maxconns_fast", "%s", settings.maxconns_fast ? "yes" : "no");
    APPEND_STAT("hashpower_init", "%d", settings.hashpower_init);
    APPEND_STAT("slab_reassign", "%s", settings.slab_reassign ? "yes" : "no");
    APPEND_STAT("slab_automove", "%d", settings.slab_automove);
    APPEND_STAT("lru_crawler", "%s", settings.lru_crawler ? "yes" : "no");
    APPEND_STAT("lru_crawler_sleep", "%d", settings.lru_crawler_sleep);
    APPEND_STAT("lru_crawler_tocrawl", "%lu", (unsigned long)settings.lru_crawler_tocrawl);
    APPEND_STAT("tail_repair_time", "%d", settings.tail_repair_time);
    APPEND_STAT("flush_enabled", "%s", settings.flush_enabled ? "yes" : "no");
    APPEND_STAT("hash_algorithm", "%s", settings.hash_algorithm);
}

static void conn_to_str(const conn *c, char *buf) {
    char addr_text[MAXPATHLEN];

    if (!c) {
        strcpy(buf, "<null>");
    } else if (c->state == conn_closed) {
        strcpy(buf, "<closed>");
    } else {
        const char *protoname = "?";
        struct sockaddr_in6 local_addr;
        struct sockaddr *addr = (void *)&c->request_addr;
        int af;
        unsigned short port = 0;

        /* For listen ports and idle UDP ports, show listen address */
        if (c->state == conn_listening ||
                (IS_UDP(c->transport) &&
                 c->state == conn_read)) {
            socklen_t local_addr_len = sizeof(local_addr);

            if (getsockname(c->sfd,
                        (struct sockaddr *)&local_addr,
                        &local_addr_len) == 0) {
                addr = (struct sockaddr *)&local_addr;
            }
        }

        af = addr->sa_family;
        addr_text[0] = '\0';

        switch (af) {
            case AF_INET:
                (void) inet_ntop(af,
                        &((struct sockaddr_in *)addr)->sin_addr,
                        addr_text,
                        sizeof(addr_text) - 1);
                port = ntohs(((struct sockaddr_in *)addr)->sin_port);
                protoname = IS_UDP(c->transport) ? "udp" : "tcp";
                break;

            case AF_INET6:
                addr_text[0] = '[';
                addr_text[1] = '\0';
                if (inet_ntop(af,
                        &((struct sockaddr_in6 *)addr)->sin6_addr,
                        addr_text + 1,
                        sizeof(addr_text) - 2)) {
                    strcat(addr_text, "]");
                }
                port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
                protoname = IS_UDP(c->transport) ? "udp6" : "tcp6";
                break;

            case AF_UNIX:
                strncpy(addr_text,
                        ((struct sockaddr_un *)addr)->sun_path,
                        sizeof(addr_text) - 1);
                addr_text[sizeof(addr_text)-1] = '\0';
                protoname = "unix";
                break;
        }

        if (strlen(addr_text) < 2) {
            /* Most likely this is a connected UNIX-domain client which
             * has no peer socket address, but there's no portable way
             * to tell for sure.
             */
            sprintf(addr_text, "<AF %d>", af);
        }

        if (port) {
            sprintf(buf, "%s:%s:%u", protoname, addr_text, port);
        } else {
            sprintf(buf, "%s:%s", protoname, addr_text);
        }
    }
}
#endif

/* We have an ODP pkt
 *
 */
odp_packet_t process_odp_pkt(ODP_THREAD *me, odp_packet_t pkt, odp_pool_t pool)
{
    if (settings.binding_protocol != binary_prot) {
        perror("ODP memcached only supports the binary protocol\n");
        return ODP_PACKET_INVALID;
    }

    protocol_binary_request_header *req;
    req = (protocol_binary_request_header*)odp_packet_data(pkt);

    if (settings.verbose > 1) {
        /* Dump the packet before we convert it to host order */
        int ii;
        fprintf(stderr, "< Read binary protocol data:");
        for (ii = 0; ii < sizeof(req->bytes); ++ii) {
            if (ii % 4 == 0) {
                fprintf(stderr, "\n<   ");
            }
            fprintf(stderr, " 0x%02x", req->bytes[ii]);
        }
        fprintf(stderr, "\n");
    }

    req->request.keylen = ntohs(req->request.keylen);
    req->request.bodylen = ntohl(req->request.bodylen);
    req->request.cas = ntohll(req->request.cas);

    if (req->request.magic != PROTOCOL_BINARY_REQ) {
        if (settings.verbose) {
            fprintf(stderr, "Invalid magic:  %x\n",
                    req->request.magic);
        }
        return ODP_PACKET_INVALID;
    }

    //c->cmd = c->binary_header.request.opcode;
    //c->keylen = c->binary_header.request.keylen;
    //c->opaque = c->binary_header.request.opaque;
    /* clear the returned cas value */
    //c->cas = 0;

    // dispatch_bin_command(c)
    return odp_dispatch_bin_command(me, req, pkt, pool);
}

static bool update_event(conn *c, const int new_flags) {
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;
    if (event_del(&c->event) == -1) return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
}

/*
 * Sets whether we are listening for new connections or not.
 */
void do_accept_new_conns(const bool do_accept) {
    conn *next;

    for (next = listen_conn; next; next = next->next) {
        if (do_accept) {
            update_event(next, EV_READ | EV_PERSIST);
            if (listen(next->sfd, settings.backlog) != 0) {
                perror("listen");
            }
        }
        else {
            update_event(next, 0);
            if (listen(next->sfd, 0) != 0) {
                perror("listen");
            }
        }
    }

    if (do_accept) {
        STATS_LOCK();
        stats.accepting_conns = true;
        STATS_UNLOCK();
    } else {
        STATS_LOCK();
        stats.accepting_conns = false;
        stats.listen_disabled_num++;
        STATS_UNLOCK();
        allow_new_conns = false;
        maxconns_handler(-42, 0, 0);
    }
}

/*
 * Transmit the next chunk of data from our list of msgbuf structures.
 *
 * Returns:
 *   TRANSMIT_COMPLETE   All done writing.
 *   TRANSMIT_INCOMPLETE More data remaining to write.
 *   TRANSMIT_SOFT_ERROR Can't write any more right now.
 *   TRANSMIT_HARD_ERROR Can't write (c->state is set to conn_closing)
 */
#if 0
static enum transmit_result transmit(conn *c) {
    assert(c != NULL);

    if (c->msgcurr < c->msgused &&
            c->msglist[c->msgcurr].msg_iovlen == 0) {
        /* Finished writing the current msg; advance to the next. */
        c->msgcurr++;
    }
    if (c->msgcurr < c->msgused) {
        ssize_t res;
        struct msghdr *m = &c->msglist[c->msgcurr];

        res = sendmsg(c->sfd, m, 0);
        if (res > 0) {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.bytes_written += res;
            pthread_mutex_unlock(&c->thread->stats.mutex);

            /* We've written some of the data. Remove the completed
               iovec entries from the list of pending writes. */
            while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) {
                res -= m->msg_iov->iov_len;
                m->msg_iovlen--;
                m->msg_iov++;
            }

            /* Might have written just part of the last iovec entry;
               adjust it so the next write will do the rest. */
            if (res > 0) {
                m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
                m->msg_iov->iov_len -= res;
            }
            return TRANSMIT_INCOMPLETE;
        }
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                return TRANSMIT_HARD_ERROR;
            }
            return TRANSMIT_SOFT_ERROR;
        }
        /* if res == 0 or res == -1 and error is not EAGAIN or EWOULDBLOCK,
           we have a real error, on which we close the connection */
        if (settings.verbose > 0)
            perror("Failed to write, and not due to blocking");

        if (IS_UDP(c->transport))
            conn_set_state(c, conn_read);
        else
            conn_set_state(c, conn_closing);
        return TRANSMIT_HARD_ERROR;
    } else {
        return TRANSMIT_COMPLETE;
    }
}
#endif

void event_handler(const int fd, const short which, void *arg) {
    conn *c;

    c = (conn *)arg;
    assert(c != NULL);

    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
}


static void drive_machine(conn *c) {
    bool stop = false;
//    int sfd;
//    socklen_t addrlen;
//    struct sockaddr_storage addr;
//    int nreqs = settings.reqs_per_event;
//    int res;
//    const char *str;
//#ifdef HAVE_ACCEPT4
//    static int  use_accept4 = 1;
//#else
//    static int  use_accept4 = 0;
//#endif
//    odp_queue_param_t qparam;
//    odp_queue_t qin;
//    char inq_name[256];
    odp_packetizer_t pktizer;
    odp_packetizer_entry_t pktizer_entry;
    odp_sockio_t sockio;

    assert(c != NULL);

    while (!stop) {

        switch(c->state) {
        case conn_listening:
            // Setup an ODP Socket IO queue here
            sockio = odp_sockio_open(c->sfd, c->input_pool);
            if (sockio == ODP_SOCKIO_INVALID) {
                perror("odp_sockio_open() failed");
                stop = true;
                break;
            }

            // Close a connection if we have too many
            if (settings.maxconns_fast &&
                stats.curr_conns + stats.reserved_fds >= settings.maxconns - 1) {
                odp_sockio_close(sockio);
                STATS_LOCK();
                stats.rejected_conns++;
                STATS_UNLOCK();
            }

            // Create a packetizer for the binary protocol
            pktizer_entry.pool = dispatcher_thread.output_pool;
            pktizer_entry.header_size = sizeof(protocol_binary_request_header);
            pktizer_entry.size_offset = 8; //offsetof(protocol_binary_request_header, bodylen);
            pktizer_entry.num_bytes = sizeof(uint32_t);

            pktizer = odp_packetizer_create(pktizer_entry);
            odp_assign_packetizer_sockio(sockio, pktizer, dispatcher_thread.output_pool);
            ////

	    // socket input created and packetizer available, start socket in
	    // scheduler
	    odp_socket_io_start(sockio);
            dispatcher_thread.num_queues++;

            STATS_LOCK();
            stats.curr_conns++;
            stats.total_conns++;
            STATS_UNLOCK();
            stop = true;

            break;

        case conn_closing:
            if (IS_UDP(c->transport))
                conn_cleanup(c);
            else
                conn_close(c);
            stop = true;
            break;

        case conn_closed:
            /* This only happens if dormando is an idiot. */
            abort();
            break;

        case conn_max_state:
            assert(false);
            break;
        case conn_new_cmd:
        case conn_waiting:
        case conn_read:
        case conn_parse_cmd:
        case conn_write:
        case conn_nread:
        case conn_swallow:
        case conn_mwrite:
        default:
            stop = true;
            break;
        }
    }

    return;
}

#if 0
static int new_socket(struct addrinfo *ai) {
    int sfd;
    int flags;

    if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}
#endif

/*
 * Sets a socket's send buffer size to the maximum allowed by the system.
 */
#if 0
static void maximize_sndbuf(const int sfd) {
    socklen_t intsize = sizeof(int);
    int last_good = 0;
    int min, max, avg;
    int old_size;

    /* Start with the default size. */
    if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &old_size, &intsize) != 0) {
        if (settings.verbose > 0)
            perror("getsockopt(SO_SNDBUF)");
        return;
    }

    /* Binary-search for the real maximum. */
    min = old_size;
    max = MAX_SENDBUF_SIZE;

    while (min <= max) {
        avg = ((unsigned int)(min + max)) / 2;
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (void *)&avg, intsize) == 0) {
            last_good = avg;
            min = avg + 1;
        } else {
            max = avg - 1;
        }
    }

    if (settings.verbose > 1)
        fprintf(stderr, "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
}
#endif

#if 0
/**
 * Create a socket and bind it to a specific port number
 * @param interface the interface to bind to
 * @param port the port number to bind to
 * @param transport the transport protocol (TCP / UDP)
 * @param portnumber_file A filepointer to write the port numbers to
 *        when they are successfully added to the list of ports we
 *        listen on.
 */
static int server_socket(const char *interface,
                         int port,
                         enum network_transport transport,
                         FILE *portnumber_file) {
    int sfd;
    struct linger ling = {0, 0};
    struct addrinfo *ai;
    struct addrinfo *next;
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC };
    char port_buf[NI_MAXSERV];
    int error;
    int success = 0;
    int flags =1;

    hints.ai_socktype = IS_UDP(transport) ? SOCK_DGRAM : SOCK_STREAM;

    if (port == -1) {
        port = 0;
    }
    snprintf(port_buf, sizeof(port_buf), "%d", port);
    error= getaddrinfo(interface, port_buf, &hints, &ai);
    if (error != 0) {
        if (error != EAI_SYSTEM)
          fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
        else
          perror("getaddrinfo()");
        return 1;
    }

    for (next= ai; next; next= next->ai_next) {
        conn *listen_conn_add;
        if ((sfd = new_socket(next)) == -1) {
            /* getaddrinfo can return "junk" addresses,
             * we make sure at least one works before erroring.
             */
            if (errno == EMFILE) {
                /* ...unless we're out of fds */
                perror("server_socket");
                exit(EX_OSERR);
            }
            continue;
        }

#ifdef IPV6_V6ONLY
        if (next->ai_family == AF_INET6) {
            error = setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &flags, sizeof(flags));
            if (error != 0) {
                perror("setsockopt");
                close(sfd);
                continue;
            }
        }
#endif

        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
        if (error != 0)
            perror("setsockopt");

        error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
        if (error != 0)
            perror("setsockopt");

        error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
        if (error != 0)
            perror("setsockopt");

        if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                perror("bind()");
                close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            close(sfd);
            continue;
        } else {
            success++;
            if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1) {
                perror("listen()");
                close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            if (portnumber_file != NULL &&
                (next->ai_addr->sa_family == AF_INET ||
                 next->ai_addr->sa_family == AF_INET6)) {
                union {
                    struct sockaddr_in in;
                    struct sockaddr_in6 in6;
                } my_sockaddr;
                socklen_t len = sizeof(my_sockaddr);
                if (getsockname(sfd, (struct sockaddr*)&my_sockaddr, &len)==0) {
                    if (next->ai_addr->sa_family == AF_INET) {
                        fprintf(portnumber_file, "%s INET: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in.sin_port));
                    } else {
                        fprintf(portnumber_file, "%s INET6: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in6.sin6_port));
                    }
                }
            }
        }

        if (!(listen_conn_add = conn_new(sfd, conn_listening,
                                         EV_READ | EV_PERSIST, 1,
                                         transport, main_base))) {
            fprintf(stderr, "failed to create listening connection\n");
            exit(EXIT_FAILURE);
        }
        listen_conn_add->next = listen_conn;
        listen_conn = listen_conn_add;
    }

    freeaddrinfo(ai);

    /* Return zero iff we detected no errors in starting up connections */
    return success == 0;
}

static int server_sockets(int port, enum network_transport transport,
                          FILE *portnumber_file) {
    if (settings.inter == NULL) {
        return server_socket(settings.inter, port, transport, portnumber_file);
    } else {
        // tokenize them and bind to each one of them..
        char *b;
        int ret = 0;
        char *list = strdup(settings.inter);

        if (list == NULL) {
            fprintf(stderr, "Failed to allocate memory for parsing server interface string\n");
            return 1;
        }
        for (char *p = strtok_r(list, ";,", &b);
             p != NULL;
             p = strtok_r(NULL, ";,", &b)) {
            int the_port = port;
            char *s = strchr(p, ':');
            if (s != NULL) {
                *s = '\0';
                ++s;
                if (!safe_strtol(s, &the_port)) {
                    fprintf(stderr, "Invalid port number: \"%s\"", s);
                    return 1;
                }
            }
            if (strcmp(p, "*") == 0) {
                p = NULL;
            }
            ret |= server_socket(p, the_port, transport, portnumber_file);
        }
        free(list);
        return ret;
    }
}

static int new_socket_unix(void) {
    int sfd;
    int flags;

    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}

static int server_socket_unix(const char *path, int access_mask) {
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_un addr;
    struct stat tstat;
    int flags =1;
    int old_umask;

    if (!path) {
        return 1;
    }

    if ((sfd = new_socket_unix()) == -1) {
        return 1;
    }

    /*
     * Clean up a previous socket file if we left it around
     */
    if (lstat(path, &tstat) == 0) {
        if (S_ISSOCK(tstat.st_mode))
            unlink(path);
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));

    /*
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    assert(strcmp(addr.sun_path, path) == 0);
    old_umask = umask( ~(access_mask&0777));
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        umask(old_umask);
        return 1;
    }
    umask(old_umask);
    if (listen(sfd, settings.backlog) == -1) {
        perror("listen()");
        close(sfd);
        return 1;
    }
    if (!(listen_conn = conn_new(sfd, conn_listening,
                                 EV_READ | EV_PERSIST, 1,
                                 local_transport, main_base))) {
        fprintf(stderr, "failed to create listening connection\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
#endif

/*
 * We keep the current time of day in a global variable that's updated by a
 * timer event. This saves us a bunch of time() system calls (we really only
 * need to get the time once a second, whereas there can be tens of thousands
 * of requests a second) and allows us to use server-start-relative timestamps
 * rather than absolute UNIX timestamps, a space savings on systems where
 * sizeof(time_t) > sizeof(unsigned int).
 */
volatile rel_time_t current_time;
static struct event clockevent;

/* libevent uses a monotonic clock when available for event scheduling. Aside
 * from jitter, simply ticking our internal timer here is accurate enough.
 * Note that users who are setting explicit dates for expiration times *must*
 * ensure their clocks are correct before starting memcached. */
static void clock_handler(const int fd, const short which, void *arg) {
    struct timeval t = {.tv_sec = 1, .tv_usec = 0};
    static bool initialized = false;
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    static bool monotonic = false;
    static time_t monotonic_start;
#endif

    if (initialized) {
        /* only delete the event if it's actually there. */
        evtimer_del(&clockevent);
    } else {
        initialized = true;
        /* process_started is initialized to time() - 2. We initialize to 1 so
         * flush_all won't underflow during tests. */
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            monotonic = true;
            monotonic_start = ts.tv_sec - ITEM_UPDATE_INTERVAL - 2;
        }
#endif
    }

    evtimer_set(&clockevent, clock_handler, 0);
    event_base_set(main_base, &clockevent);
    evtimer_add(&clockevent, &t);

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    if (monotonic) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
            return;
        current_time = (rel_time_t) (ts.tv_sec - monotonic_start);
        return;
    }
#endif
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        current_time = (rel_time_t) (tv.tv_sec - process_started);
    }
}

static void usage(void) {
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      TCP port number to listen on (default: 11211)\n"
           "-U <num>      UDP port number to listen on (default: 11211, 0 is off)\n"
           "-s <file>     UNIX socket path to listen on (disables network support)\n"
           "-A            enable ascii \"shutdown\" command\n"
           "-a <mask>     access mask for UNIX socket, in octal (default: 0700)\n"
           "-l <addr>     interface to listen on (default: INADDR_ANY, all addresses)\n"
           "              <addr> may be specified as host:port. If you don't specify\n"
           "              a port number, the value you specified with -p or -U is\n"
           "              used. You may specify multiple addresses separated by comma\n"
           "              or by using -l multiple times\n"

           "-d            run as a daemon\n"
           "-r            maximize core file limit\n"
           "-u <username> assume identity of <username> (only when run as root)\n"
           "-m <num>      max memory to use for items in megabytes (default: 64 MB)\n"
           "-M            return error on memory exhausted (rather than removing items)\n"
           "-c <num>      max simultaneous connections (default: 1024)\n"
           "-k            lock down all paged memory.  Note that there is a\n"
           "              limit on how much memory you may lock.  Trying to\n"
           "              allocate more than that would fail, so be sure you\n"
           "              set the limit correctly for the user you started\n"
           "              the daemon with (not for -u <username> user;\n"
           "              under sh this is done with 'ulimit -S -l NUM_KB').\n"
           "-v            verbose (print errors/warnings while in event loop)\n"
           "-vv           very verbose (also print client commands/reponses)\n"
           "-vvv          extremely verbose (also print internal state transitions)\n"
           "-h            print this help and exit\n"
           "-i            print memcached and libevent license\n"
           "-P <file>     save PID in <file>, only used with -d option\n"
           "-f <factor>   chunk size growth factor (default: 1.25)\n"
           "-n <bytes>    minimum space allocated for key+value+flags (default: 48)\n");
    printf("-L            Try to use large memory pages (if available). Increasing\n"
           "              the memory page size could reduce the number of TLB misses\n"
           "              and improve the performance. In order to get large pages\n"
           "              from the OS, memcached will allocate the total item-cache\n"
           "              in one large chunk.\n");
    printf("-D <char>     Use <char> as the delimiter between key prefixes and IDs.\n"
           "              This is used for per-prefix stats reporting. The default is\n"
           "              \":\" (colon). If this option is specified, stats collection\n"
           "              is turned on automatically; if not, then it may be turned on\n"
           "              by sending the \"stats detail on\" command to the server.\n");
    printf("-t <num>      number of threads to use (default: 4)\n");
    printf("-R            Maximum number of requests per event, limits the number of\n"
           "              requests process for a given connection to prevent \n"
           "              starvation (default: 20)\n");
    printf("-C            Disable use of CAS\n");
    printf("-b            Set the backlog queue limit (default: 1024)\n");
    printf("-B            Binding protocol - one of ascii, binary, or auto (default)\n");
    printf("-I            Override the size of each slab page. Adjusts max item size\n"
           "              (default: 1mb, min: 1k, max: 128m)\n");
#ifdef ENABLE_SASL
    printf("-S            Turn on Sasl authentication\n");
#endif
    printf("-F            Disable flush_all command\n");
    printf("-o            Comma separated list of extended or experimental options\n"
           "              - (EXPERIMENTAL) maxconns_fast: immediately close new\n"
           "                connections if over maxconns limit\n"
           "              - hashpower: An integer multiplier for how large the hash\n"
           "                table should be. Can be grown at runtime if not big enough.\n"
           "                Set this based on \"STAT hash_power_level\" before a \n"
           "                restart.\n"
           "              - tail_repair_time: Time in seconds that indicates how long to wait before\n"
           "                forcefully taking over the LRU tail item whose refcount has leaked.\n"
           "                The default is 3 hours.\n"
           "              - hash_algorithm: The hash table algorithm\n"
           "                default is jenkins hash. options: jenkins, murmur3\n"
           "              - lru_crawler: Enable LRU Crawler background thread\n"
           "              - lru_crawler_sleep: Microseconds to sleep between items\n"
           "                default is 100.\n"
           "              - lru_crawler_tocrawl: Max items to crawl per slab per run\n"
           "                default is 0 (unlimited)\n"
           );
    return;
}

static void usage_license(void) {
    printf(PACKAGE " " VERSION "\n\n");
    printf(
    "Copyright (c) 2003, Danga Interactive, Inc. <http://www.danga.com/>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions are\n"
    "met:\n"
    "\n"
    "    * Redistributions of source code must retain the above copyright\n"
    "notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "    * Redistributions in binary form must reproduce the above\n"
    "copyright notice, this list of conditions and the following disclaimer\n"
    "in the documentation and/or other materials provided with the\n"
    "distribution.\n"
    "\n"
    "    * Neither the name of the Danga Interactive nor the names of its\n"
    "contributors may be used to endorse or promote products derived from\n"
    "this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
    "\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
    "LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
    "A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
    "OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
    "SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
    "LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
    "OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    "\n"
    "\n"
    "This product includes software developed by Niels Provos.\n"
    "\n"
    "[ libevent ]\n"
    "\n"
    "Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions\n"
    "are met:\n"
    "1. Redistributions of source code must retain the above copyright\n"
    "   notice, this list of conditions and the following disclaimer.\n"
    "2. Redistributions in binary form must reproduce the above copyright\n"
    "   notice, this list of conditions and the following disclaimer in the\n"
    "   documentation and/or other materials provided with the distribution.\n"
    "3. All advertising materials mentioning features or use of this software\n"
    "   must display the following acknowledgement:\n"
    "      This product includes software developed by Niels Provos.\n"
    "4. The name of the author may not be used to endorse or promote products\n"
    "   derived from this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
    "IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
    "OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
    "IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
    "INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
    "NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
    "THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    );

    return;
}

static void save_pid(const char *pid_file) {
    FILE *fp;
    if (access(pid_file, F_OK) == 0) {
        if ((fp = fopen(pid_file, "r")) != NULL) {
            char buffer[1024];
            if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                unsigned int pid;
                if (safe_strtoul(buffer, &pid) && kill((pid_t)pid, 0) == 0) {
                    fprintf(stderr, "WARNING: The pid file contained the following (running) pid: %u\n", pid);
                }
            }
            fclose(fp);
        }
    }

    /* Create the pid file first with a temporary name, then
     * atomically move the file to the real name to avoid a race with
     * another process opening the file to read the pid, but finding
     * it empty.
     */
    char tmp_pid_file[1024];
    snprintf(tmp_pid_file, sizeof(tmp_pid_file), "%s.tmp", pid_file);

    if ((fp = fopen(tmp_pid_file, "w")) == NULL) {
        vperror("Could not open the pid file %s for writing", tmp_pid_file);
        return;
    }

    fprintf(fp,"%ld\n", (long)getpid());
    if (fclose(fp) == -1) {
        vperror("Could not close the pid file %s", tmp_pid_file);
    }

    if (rename(tmp_pid_file, pid_file) != 0) {
        vperror("Could not rename the pid file from %s to %s",
                tmp_pid_file, pid_file);
    }
}

static void remove_pidfile(const char *pid_file) {
  if (pid_file == NULL)
      return;

  if (unlink(pid_file) != 0) {
      vperror("Could not remove the pid file %s", pid_file);
  }

}

static void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    exit(EXIT_SUCCESS);
}

#ifndef HAVE_SIGIGNORE
static int sigignore(int sig) {
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }
    return 0;
}
#endif


/*
 * On systems that supports multiple page sizes we may reduce the
 * number of TLB-misses by using the biggest available page size
 */
static int enable_large_pages(void) {
#if defined(HAVE_GETPAGESIZES) && defined(HAVE_MEMCNTL)
    int ret = -1;
    size_t sizes[32];
    int avail = getpagesizes(sizes, 32);
    if (avail != -1) {
        size_t max = sizes[0];
        struct memcntl_mha arg = {0};
        int ii;

        for (ii = 1; ii < avail; ++ii) {
            if (max < sizes[ii]) {
                max = sizes[ii];
            }
        }

        arg.mha_flags   = 0;
        arg.mha_pagesize = max;
        arg.mha_cmd = MHA_MAPSIZE_BSSBRK;

        if (memcntl(0, 0, MC_HAT_ADVISE, (caddr_t)&arg, 0, 0) == -1) {
            fprintf(stderr, "Failed to set large pages: %s\n",
                    strerror(errno));
            fprintf(stderr, "Will use default page size\n");
        } else {
            ret = 0;
        }
    } else {
        fprintf(stderr, "Failed to get supported pagesizes: %s\n",
                strerror(errno));
        fprintf(stderr, "Will use default page size\n");
    }

    return ret;
#else
    return -1;
#endif
}

/**
 * Do basic sanity check of the runtime environment
 * @return true if no errors found, false if we can't use this env
 */
static bool sanitycheck(void) {
    /* One of our biggest problems is old and bogus libevents */
    const char *ever = event_get_version();
    if (ever != NULL) {
        if (strncmp(ever, "1.", 2) == 0) {
            /* Require at least 1.3 (that's still a couple of years old) */
            if ((ever[2] == '1' || ever[2] == '2') && !isdigit(ever[3])) {
                fprintf(stderr, "You are using libevent %s.\nPlease upgrade to"
                        " a more recent version (1.3 or newer)\n",
                        event_get_version());
                return false;
            }
        }
    }

    return true;
}

int main (int argc, char **argv) {
    int c;
    bool lock_memory = false;
    bool do_daemonize = false;
    bool preallocate = false;
    int maxcore = 0;
    char *username = NULL;
    char *pid_file = NULL;
    struct passwd *pw;
    struct rlimit rlim;
    char *buf;
    char unit = '\0';
    int size_max = 0;
    int retval = EXIT_SUCCESS;
    /* listening sockets */
    static int *l_socket = NULL;

    /* udp socket */
    static int *u_socket = NULL;
    bool protocol_specified = false;
    bool tcp_specified = false;
    bool udp_specified = false;
    enum hashfunc_type hash_type = JENKINS_HASH;
    uint32_t tocrawl;

    char *subopts;
    char *subopts_value;
    enum {
        MAXCONNS_FAST = 0,
        HASHPOWER_INIT,
        SLAB_REASSIGN,
        SLAB_AUTOMOVE,
        TAIL_REPAIR_TIME,
        HASH_ALGORITHM,
        LRU_CRAWLER,
        LRU_CRAWLER_SLEEP,
        LRU_CRAWLER_TOCRAWL
    };
    char *const subopts_tokens[] = {
        [MAXCONNS_FAST] = "maxconns_fast",
        [HASHPOWER_INIT] = "hashpower",
        [SLAB_REASSIGN] = "slab_reassign",
        [SLAB_AUTOMOVE] = "slab_automove",
        [TAIL_REPAIR_TIME] = "tail_repair_time",
        [HASH_ALGORITHM] = "hash_algorithm",
        [LRU_CRAWLER] = "lru_crawler",
        [LRU_CRAWLER_SLEEP] = "lru_crawler_sleep",
        [LRU_CRAWLER_TOCRAWL] = "lru_crawler_tocrawl",
        NULL
    };

    /** XXX ODP variables **/
    odp_pool_t input_pool;
    odp_pool_param_t input_pool_params;
    odp_pool_t output_pool;
    odp_pool_param_t output_pool_params;
    odp_pool_t notify_pool;
    odp_pool_param_t notify_pool_params;
    /***********************/

    if (!sanitycheck()) {
        return EX_OSERR;
    }

    /* handle SIGINT */
    signal(SIGINT, sig_handler);

    /* init settings */
    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    /* process arguments */
    while (-1 != (c = getopt(argc, argv,
          "a:"  /* access mask for unix socket */
          "A"  /* enable admin shutdown commannd */
          "p:"  /* TCP port number to listen on */
          "s:"  /* unix socket path to listen on */
          "U:"  /* UDP port number to listen on */
          "m:"  /* max memory to use for items in megabytes */
          "M"   /* return error on memory exhausted */
          "c:"  /* max simultaneous connections */
          "k"   /* lock down all paged memory */
          "hi"  /* help, licence info */
          "r"   /* maximize core file limit */
          "v"   /* verbose */
          "d"   /* daemon mode */
          "l:"  /* interface to listen on */
          "u:"  /* user identity to run as */
          "P:"  /* save PID in file */
          "f:"  /* factor? */
          "n:"  /* minimum space allocated for key+value+flags */
          "t:"  /* threads */
          "D:"  /* prefix delimiter? */
          "L"   /* Large memory pages */
          "R:"  /* max requests per event */
          "C"   /* Disable use of CAS */
          "b:"  /* backlog queue limit */
          "B:"  /* Binding protocol */
          "I:"  /* Max item size */
          "S"   /* Sasl ON */
          "F"   /* Disable flush_all */
          "o:"  /* Extended generic options */
          /** ODP OPTIONS **/
          "w:"  /* ODP input pkt buffer size */
          "W:"  /* ODP input pkt buffer pool total size */
          "x:"  /* ODP output/pktizer pkt buffer size */
          "X:"  /* ODP output/pktizer pkt buffer pool total size */
          "Z:"   /* ODP IO Thread creation */
        ))) {
        switch (c) {
        case 'A':
            /* enables "shutdown" command */
            settings.shutdown_command = true;
            break;

        case 'a':
            /* access for unix domain socket, as octal mask (like chmod)*/
            settings.access= strtol(optarg,NULL,8);
            break;

        case 'U':
            settings.udpport = atoi(optarg);
            udp_specified = true;
            break;
        case 'p':
            settings.port = atoi(optarg);
            tcp_specified = true;
            break;
        case 's':
            settings.socketpath = optarg;
            break;
        case 'm':
            settings.maxbytes = ((size_t)atoi(optarg)) * 1024 * 1024;
            break;
        case 'M':
            settings.evict_to_free = 0;
            break;
        case 'c':
            settings.maxconns = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'i':
            usage_license();
            exit(EXIT_SUCCESS);
        case 'k':
            lock_memory = true;
            break;
        case 'v':
            settings.verbose++;
            break;
        case 'l':
            if (settings.inter != NULL) {
                size_t len = strlen(settings.inter) + strlen(optarg) + 2;
                char *p = malloc(len);
                if (p == NULL) {
                    fprintf(stderr, "Failed to allocate memory\n");
                    return 1;
                }
                snprintf(p, len, "%s,%s", settings.inter, optarg);
                free(settings.inter);
                settings.inter = p;
            } else {
                settings.inter= strdup(optarg);
            }
            break;
        case 'd':
            do_daemonize = true;
            break;
        case 'r':
            maxcore = 1;
            break;
        case 'R':
            settings.reqs_per_event = atoi(optarg);
            if (settings.reqs_per_event == 0) {
                fprintf(stderr, "Number of requests per event must be greater than 0\n");
                return 1;
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'P':
            pid_file = optarg;
            break;
        case 'f':
            settings.factor = atof(optarg);
            if (settings.factor <= 1.0) {
                fprintf(stderr, "Factor must be greater than 1\n");
                return 1;
            }
            break;
        case 'n':
            settings.chunk_size = atoi(optarg);
            if (settings.chunk_size == 0) {
                fprintf(stderr, "Chunk size must be greater than 0\n");
                return 1;
            }
            break;
        case 't':
            settings.num_threads = atoi(optarg);
            if (settings.num_threads <= 0) {
                fprintf(stderr, "Number of threads must be greater than 0\n");
                return 1;
            }
            /* There're other problems when you get above 64 threads.
             * In the future we should portably detect # of cores for the
             * default.
             */
            if (settings.num_threads > 64) {
                fprintf(stderr, "WARNING: Setting a high number of worker"
                                "threads is not recommended.\n"
                                " Set this value to the number of cores in"
                                " your machine or less.\n");
            }
            break;
        case 'D':
            if (! optarg || ! optarg[0]) {
                fprintf(stderr, "No delimiter specified\n");
                return 1;
            }
            settings.prefix_delimiter = optarg[0];
            settings.detail_enabled = 1;
            break;
        case 'L' :
            if (enable_large_pages() == 0) {
                preallocate = true;
            } else {
                fprintf(stderr, "Cannot enable large pages on this system\n"
                    "(There is no Linux support as of this version)\n");
                return 1;
            }
            break;
        case 'C' :
            settings.use_cas = false;
            break;
        case 'b' :
            settings.backlog = atoi(optarg);
            break;
        case 'B':
            protocol_specified = true;
            if (strcmp(optarg, "auto") == 0) {
                settings.binding_protocol = negotiating_prot;
            } else if (strcmp(optarg, "binary") == 0) {
                settings.binding_protocol = binary_prot;
            } else if (strcmp(optarg, "ascii") == 0) {
                settings.binding_protocol = ascii_prot;
            } else {
                fprintf(stderr, "Invalid value for binding protocol: %s\n"
                        " -- should be one of auto, binary, or ascii\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'I':
            buf = strdup(optarg);
            unit = buf[strlen(buf)-1];
            if (unit == 'k' || unit == 'm' ||
                unit == 'K' || unit == 'M') {
                buf[strlen(buf)-1] = '\0';
                size_max = atoi(buf);
                if (unit == 'k' || unit == 'K')
                    size_max *= 1024;
                if (unit == 'm' || unit == 'M')
                    size_max *= 1024 * 1024;
                settings.item_size_max = size_max;
            } else {
                settings.item_size_max = atoi(buf);
            }
            if (settings.item_size_max < 1024) {
                fprintf(stderr, "Item max size cannot be less than 1024 bytes.\n");
                return 1;
            }
            if (settings.item_size_max > 1024 * 1024 * 128) {
                fprintf(stderr, "Cannot set item size limit higher than 128 mb.\n");
                return 1;
            }
            if (settings.item_size_max > 1024 * 1024) {
                fprintf(stderr, "WARNING: Setting item max size above 1MB is not"
                    " recommended!\n"
                    " Raising this limit increases the minimum memory requirements\n"
                    " and will decrease your memory efficiency.\n"
                );
            }
            free(buf);
            break;
        case 'S': /* set Sasl authentication to true. Default is false */
#ifndef ENABLE_SASL
            fprintf(stderr, "This server is not built with SASL support.\n");
            exit(EX_USAGE);
#endif
            settings.sasl = true;
            break;
        case 'F' :
            settings.flush_enabled = false;
            break;
        case 'o': /* It's sub-opts time! */
            subopts = optarg;

            while (*subopts != '\0') {

            switch (getsubopt(&subopts, subopts_tokens, &subopts_value)) {
            case MAXCONNS_FAST:
                settings.maxconns_fast = true;
                break;
            case HASHPOWER_INIT:
                if (subopts_value == NULL) {
                    fprintf(stderr, "Missing numeric argument for hashpower\n");
                    return 1;
                }
                settings.hashpower_init = atoi(subopts_value);
                if (settings.hashpower_init < 12) {
                    fprintf(stderr, "Initial hashtable multiplier of %d is too low\n",
                        settings.hashpower_init);
                    return 1;
                } else if (settings.hashpower_init > 64) {
                    fprintf(stderr, "Initial hashtable multiplier of %d is too high\n"
                        "Choose a value based on \"STAT hash_power_level\" from a running instance\n",
                        settings.hashpower_init);
                    return 1;
                }
                break;
            case SLAB_REASSIGN:
                settings.slab_reassign = true;
                break;
            case SLAB_AUTOMOVE:
                if (subopts_value == NULL) {
                    settings.slab_automove = 1;
                    break;
                }
                settings.slab_automove = atoi(subopts_value);
                if (settings.slab_automove < 0 || settings.slab_automove > 2) {
                    fprintf(stderr, "slab_automove must be between 0 and 2\n");
                    return 1;
                }
                break;
            case TAIL_REPAIR_TIME:
                if (subopts_value == NULL) {
                    fprintf(stderr, "Missing numeric argument for tail_repair_time\n");
                    return 1;
                }
                settings.tail_repair_time = atoi(subopts_value);
                if (settings.tail_repair_time < 10) {
                    fprintf(stderr, "Cannot set tail_repair_time to less than 10 seconds\n");
                    return 1;
                }
                break;
            case HASH_ALGORITHM:
                if (subopts_value == NULL) {
                    fprintf(stderr, "Missing hash_algorithm argument\n");
                    return 1;
                };
                if (strcmp(subopts_value, "jenkins") == 0) {
                    hash_type = JENKINS_HASH;
                } else if (strcmp(subopts_value, "murmur3") == 0) {
                    hash_type = MURMUR3_HASH;
                } else {
                    fprintf(stderr, "Unknown hash_algorithm option (jenkins, murmur3)\n");
                    return 1;
                }
                break;
            case LRU_CRAWLER:
                if (start_item_crawler_thread() != 0) {
                    fprintf(stderr, "Failed to enable LRU crawler thread\n");
                    return 1;
                }
                break;
            case LRU_CRAWLER_SLEEP:
                settings.lru_crawler_sleep = atoi(subopts_value);
                if (settings.lru_crawler_sleep > 1000000 || settings.lru_crawler_sleep < 0) {
                    fprintf(stderr, "LRU crawler sleep must be between 0 and 1 second\n");
                    return 1;
                }
                break;
            case LRU_CRAWLER_TOCRAWL:
                if (!safe_strtoul(subopts_value, &tocrawl)) {
                    fprintf(stderr, "lru_crawler_tocrawl takes a numeric 32bit value\n");
                    return 1;
                }
                settings.lru_crawler_tocrawl = tocrawl;
                break;
            default:
                printf("Illegal suboption \"%s\"\n", subopts_value);
                return 1;
            }

            }
            break;
        case 'w':
            settings.input_pkt_size = atoi(optarg);
            if (settings.input_pkt_size < MIN_ODP_BUFFER_SIZE) {
                printf("Input pkt size must be at least %dB\n", MIN_ODP_BUFFER_SIZE);
                return 1;
            }

            /* Make the pool size of multiple of the pkt size */
            if (settings.input_pkt_pool_size != 0 &&
                settings.input_pkt_pool_size % settings.input_pkt_size) {
                settings.input_pkt_pool_size = (settings.input_pkt_pool_size / settings.input_pkt_size) * settings.input_pkt_size + settings.input_pkt_size;
            }
            break;
        case 'W':
            settings.input_pkt_pool_size = atoi(optarg);
            if (settings.input_pkt_size != 0 &&
                settings.input_pkt_pool_size % settings.input_pkt_size) {
                settings.input_pkt_pool_size = (settings.input_pkt_pool_size / settings.input_pkt_size) * settings.input_pkt_size + settings.input_pkt_size;
            }
            break;
        case 'x':
            settings.output_pkt_size = atoi(optarg);

            if (settings.output_pkt_size < MIN_ODP_BUFFER_SIZE) {
                printf("Output pkt size must be at least %dB\n", MIN_ODP_BUFFER_SIZE);
                return 1;
            }

            if (settings.output_pkt_pool_size != 0 &&
                settings.output_pkt_pool_size % settings.output_pkt_size) {
                settings.output_pkt_pool_size = (settings.output_pkt_pool_size / settings.output_pkt_size) * settings.output_pkt_size + settings.output_pkt_size;
            }
            break;
        case 'X':
            settings.output_pkt_pool_size = atoi(optarg);
            if (settings.output_pkt_pool_size != 0 &&
                settings.output_pkt_pool_size % settings.output_pkt_size) {
                settings.output_pkt_pool_size = (settings.output_pkt_pool_size / settings.output_pkt_size) * settings.output_pkt_size + settings.output_pkt_size;
            }
            break;
	case 'Z':
            settings.num_io_threads = atoi(optarg);
	    break;
        default:
            fprintf(stderr, "Illegal argument \"%c\"\n", c);
            return 1;
        }
    }

    if (hash_init(hash_type) != 0) {
        fprintf(stderr, "Failed to initialize hash_algorithm!\n");
        exit(EX_USAGE);
    }

    /*
     * Use one workerthread to serve each UDP port if the user specified
     * multiple ports
     */
    if (settings.inter != NULL && strchr(settings.inter, ',')) {
        settings.num_threads_per_udp = 1;
    } else {
        settings.num_threads_per_udp = settings.num_threads;
    }

    if (settings.sasl) {
        if (!protocol_specified) {
            settings.binding_protocol = binary_prot;
        } else {
            if (settings.binding_protocol != binary_prot) {
                fprintf(stderr, "ERROR: You cannot allow the ASCII protocol while using SASL.\n");
                exit(EX_USAGE);
            }
        }
    }

    if (tcp_specified && !udp_specified) {
        settings.udpport = settings.port;
    } else if (udp_specified && !tcp_specified) {
        settings.port = settings.udpport;
    }

    if (maxcore != 0) {
        struct rlimit rlim_new;
        /*
         * First try raising to infinity; if that fails, try bringing
         * the soft limit to the hard.
         */
        if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
            rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &rlim_new)!= 0) {
                /* failed. try raising just to the old max */
                rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
                (void)setrlimit(RLIMIT_CORE, &rlim_new);
            }
        }
        /*
         * getrlimit again to see what we ended up with. Only fail if
         * the soft limit ends up 0, because then no core files will be
         * created at all.
         */

        if ((getrlimit(RLIMIT_CORE, &rlim) != 0) || rlim.rlim_cur == 0) {
            fprintf(stderr, "failed to ensure corefile creation\n");
            exit(EX_OSERR);
        }
    }

    /*
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */

    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        fprintf(stderr, "failed to getrlimit number of files\n");
        exit(EX_OSERR);
    } else {
        rlim.rlim_cur = settings.maxconns;
        rlim.rlim_max = settings.maxconns;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            fprintf(stderr, "failed to set rlimit for open files. Try starting as root or requesting smaller maxconns value.\n");
            exit(EX_OSERR);
        }
    }

    /* lose root privileges if we have them */
    if (getuid() == 0 || geteuid() == 0) {
        if (username == 0 || *username == '\0') {
            fprintf(stderr, "can't run as root without the -u switch\n");
            exit(EX_USAGE);
        }
        if ((pw = getpwnam(username)) == 0) {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            exit(EX_NOUSER);
        }
        if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            exit(EX_OSERR);
        }
    }

    /* Initialize Sasl if -S was specified */
    if (settings.sasl) {
        init_sasl();
    }

    /* daemonize if requested */
    /* if we want to ensure our ability to dump core, don't chdir to / */
    if (do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            perror("Failed to ignore SIGHUP");
        }
        if (daemonize(maxcore, settings.verbose) == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            exit(EXIT_FAILURE);
        }
    }

    /* lock paged memory if needed */
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        int res = mlockall(MCL_CURRENT | MCL_FUTURE);
        if (res != 0) {
            fprintf(stderr, "warning: -k invalid, mlockall() failed: %s\n",
                    strerror(errno));
        }
#else
        fprintf(stderr, "warning: -k invalid, mlockall() not supported on this platform.  proceeding without.\n");
#endif
    }

    // XXX XXX XXX XXX XXX //
    /***** ODP initialization here *****/
    if (odp_init_global(&instance, NULL, NULL)) {
        printf("Error: ODP global init failed.\n");
        exit(EXIT_FAILURE);
    }

    if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
        printf("Error: ODP local init failed.\n");
        exit(EXIT_FAILURE);
    }

    // Allocate the memory pools here

    memset(&input_pool_params, 0, sizeof(input_pool_params));
    memset(&output_pool_params, 0, sizeof(output_pool_params));

    input_pool_params.pkt.len = settings.input_pkt_size;
    //input_pool_params.buf.align = ODP_CACHE_LINE_SIZE;
    input_pool_params.pkt.seg_len = settings.input_pkt_size;
    input_pool_params.pkt.num = settings.input_pkt_pool_size /
                                    settings.input_pkt_size;
    input_pool_params.type = ODP_EVENT_PACKET;
    input_pool = odp_pool_create("input_pkt_pool", &input_pool_params);

    output_pool_params.pkt.len = settings.output_pkt_size;
    //output_pool_params.buf.align = ODP_CACHE_LINE_SIZE;
    output_pool_params.pkt.seg_len = settings.output_pkt_size;
    output_pool_params.pkt.num = settings.output_pkt_pool_size /
                                    settings.output_pkt_size;
    output_pool_params.type = ODP_EVENT_PACKET;
    output_pool = odp_pool_create("output_pkt_pool", &output_pool_params);

    notify_pool_params.pkt.len = 256;
    //notify_pool_params.buf.align = ODP_CACHE_LINE_SIZE;
    notify_pool_params.pkt.seg_len = 256;
    notify_pool_params.pkt.num = 8192;
    notify_pool_params.type = ODP_EVENT_PACKET;
    notify_pool = odp_pool_create("notify_pkt_pool", &notify_pool_params);

    if (output_pool == ODP_POOL_INVALID ||
        input_pool == ODP_POOL_INVALID ||
        notify_pool == ODP_POOL_INVALID) {
        printf("Error: ODP could not allocate buffers!\n");
        exit(EXIT_FAILURE);
    }

    if (settings.binding_protocol != binary_prot) {
        printf("Error: ODP only functions with the binary protocol!\n");
        exit(EXIT_FAILURE);
    }
    /**********************************************/

    /* initialize main thread libevent instance */
    main_base = event_init();

    /* initialize other stuff */
    stats_init();
    assoc_init(settings.hashpower_init);
    conn_init();
    slabs_init(settings.maxbytes, settings.factor, preallocate);

    /*
     * ignore SIGPIPE signals; we can use errno == EPIPE if we
     * need that information
     */
    if (sigignore(SIGPIPE) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        exit(EX_OSERR);
    }
    /* start up worker threads if MT mode */
    assert(settings.num_io_threads <= settings.num_threads);
    if (settings.num_io_threads == 0)
        settings.num_io_threads = settings.num_threads;
    thread_init_odp(settings.num_threads, settings.num_io_threads, main_base);

    if (start_assoc_maintenance_thread() == -1) {
        exit(EXIT_FAILURE);
    }

    if (settings.slab_reassign &&
        start_slab_maintenance_thread() == -1) {
        exit(EXIT_FAILURE);
    }

    /* Run regardless of initializing it later */
    init_lru_crawler();

    /* initialise clock event */
    clock_handler(0, 0, 0);

    /* create unix mode sockets after dropping privileges */
#if 0
    if (settings.socketpath != NULL) {
        errno = 0;
        if (server_socket_unix(settings.socketpath,settings.access)) {
            vperror("failed to listen on UNIX socket: %s", settings.socketpath);
            exit(EX_OSERR);
        }
    }
#endif
    if (settings.socketpath != NULL) {
        assert(0);
    }

    /* create the listening socket, bind it, and init */
    if (settings.socketpath == NULL) {
        const char *portnumber_filename = getenv("MEMCACHED_PORT_FILENAME");
#if 0
        char temp_portnumber_filename[PATH_MAX];
        FILE *portnumber_file = NULL;
        conn *next = NULL;
#endif

        if (portnumber_filename != NULL) {
            assert(0);
#if 0
            snprintf(temp_portnumber_filename,
                     sizeof(temp_portnumber_filename),
                     "%s.lck", portnumber_filename);

            portnumber_file = fopen(temp_portnumber_filename, "a");
            if (portnumber_file == NULL) {
                fprintf(stderr, "Failed to open \"%s\": %s\n",
                        temp_portnumber_filename, strerror(errno));
            }
#endif
        }

#if 0
        errno = 0;
        if (settings.port && server_sockets(settings.port, tcp_transport,
                                           portnumber_file)) {
            vperror("failed to listen on TCP port %d", settings.port);
            exit(EX_OSERR);
        }
#endif
	odp_sockio_t listener = odp_sockio_create_listener(settings.port, NULL);
	if (listener == ODP_SOCKIO_INVALID) {
	    assert(0);
	    return -1;
	}

        /*
         * initialization order: first create the listening sockets
         * (may need root on low ports), then drop root if needed,
         * then daemonise if needed, then init libevent (in some cases
         * descriptors created by libevent wouldn't survive forking).
         */
        // No UDP ports supported for now with ODP port

        /*** ODP STUFF HERE FOR NOW, not very elegant I know ***/
#if 0
        for (next = listen_conn; next; next = next->next) {
            next->input_pool = input_pool; // give the listening connection
                                           // pointers to the buffer pools
            next->output_pool = output_pool;
        }
#endif
        /*******************************************************/
    }

    /* Give the sockets a moment to open. I know this is dumb, but the error
     * is only an advisory.
     */
    usleep(1000);
    if (stats.curr_conns + stats.reserved_fds >= settings.maxconns - 1) {
        fprintf(stderr, "Maxconns setting is too low, use -c to increase.\n");
        exit(EXIT_FAILURE);
    }

    if (pid_file != NULL) {
        save_pid(pid_file);
    }

    /* Drop privileges no longer needed */
    drop_privileges();

#if 0
    /* enter the event loop */
    if (event_base_loop(main_base, 0) != 0) {
        retval = EXIT_FAILURE;
    }
#endif
    // Just sleep forever for now.
    while (1) {
        sleep(1000);
    }

    stop_assoc_maintenance_thread();

    /* remove the PID file if we're a daemon */
    if (do_daemonize)
        remove_pidfile(pid_file);
    /* Clean up strdup() call for bind() address */
    if (settings.inter)
      free(settings.inter);
    if (l_socket)
      free(l_socket);
    if (u_socket)
      free(u_socket);

    return retval;
}
