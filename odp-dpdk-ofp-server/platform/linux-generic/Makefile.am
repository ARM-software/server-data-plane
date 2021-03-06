# Uncomment this if you need to change the CUSTOM_STR string
#export CUSTOM_STR=https://git.linaro.org/lng/odp.git

include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_api.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(srcdir)/include/odp/api/align.h \
		  $(srcdir)/include/odp/api/atomic.h \
		  $(srcdir)/include/odp/api/barrier.h \
		  $(srcdir)/include/odp/api/buffer.h \
		  $(srcdir)/include/odp/api/byteorder.h \
          $(srcdir)/include/odp/api/chained_buffer.h \
		  $(srcdir)/include/odp/api/classification.h \
		  $(srcdir)/include/odp/api/compiler.h \
		  $(srcdir)/include/odp/api/cpu.h \
		  $(srcdir)/include/odp/api/cpumask.h \
		  $(srcdir)/include/odp/api/crypto.h \
		  $(srcdir)/include/odp/api/debug.h \
		  $(srcdir)/include/odp/api/errno.h \
          $(srcdir)/include/odp/api/epoll.h \
		  $(srcdir)/include/odp/api/event.h \
          $(srcdir)/include/odp/api/file_io.h \
		  $(srcdir)/include/odp/api/hash.h \
		  $(srcdir)/include/odp/api/hints.h \
		  $(srcdir)/include/odp/api/init.h \
		  $(srcdir)/include/odp/api/packet_flags.h \
		  $(srcdir)/include/odp/api/packet.h \
		  $(srcdir)/include/odp/api/packet_io.h \
		  $(srcdir)/include/odp/api/packet_io_stats.h \
		  $(srcdir)/include/odp/api/pool.h \
		  $(srcdir)/include/odp/api/queue.h \
		  $(srcdir)/include/odp/api/random.h \
		  $(srcdir)/include/odp/api/rwlock.h \
		  $(srcdir)/include/odp/api/rwlock_recursive.h \
		  $(srcdir)/include/odp/api/schedule.h \
		  $(srcdir)/include/odp/api/schedule_types.h \
		  $(srcdir)/include/odp/api/shared_memory.h \
		  $(srcdir)/include/odp/api/spinlock.h \
		  $(srcdir)/include/odp/api/spinlock_recursive.h \
		  $(srcdir)/include/odp/api/std_clib.h \
		  $(srcdir)/include/odp/api/std_types.h \
		  $(srcdir)/include/odp/api/sync.h \
		  $(srcdir)/include/odp/api/system_info.h \
		  $(srcdir)/include/odp/api/thread.h \
		  $(srcdir)/include/odp/api/thrmask.h \
		  $(srcdir)/include/odp/api/ticketlock.h \
		  $(srcdir)/include/odp/api/time.h \
		  $(srcdir)/include/odp/api/timer.h \
		  $(srcdir)/include/odp/api/traffic_mngr.h \
          $(srcdir)/include/odp/api/socket_io.h \
          $(srcdir)/include/odp/api/stream_packetizer.h \
          $(srcdir)/include/odp/api/pthreadlock.h \
		  $(srcdir)/include/odp/api/version.h \
		  $(srcdir)/include/odp/api/visibility_begin.h \
		  $(srcdir)/include/odp/api/visibility_end.h \
		  $(srcdir)/arch/@ARCH_DIR@/odp/api/cpu_arch.h

odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  $(srcdir)/include/odp/api/plat/atomic_types.h \
		  $(srcdir)/include/odp/api/plat/barrier_types.h \
		  $(srcdir)/include/odp/api/plat/buffer_types.h \
		  $(srcdir)/include/odp/api/plat/byteorder_types.h \
		  $(srcdir)/include/odp/api/plat/classification_types.h \
		  $(srcdir)/include/odp/api/plat/cpumask_types.h \
		  $(srcdir)/include/odp/api/plat/crypto_types.h \
		  $(srcdir)/include/odp/api/plat/event_types.h \
		  $(srcdir)/include/odp/api/plat/init_types.h \
		  $(srcdir)/include/odp/api/plat/packet_types.h \
		  $(srcdir)/include/odp/api/plat/packet_io_types.h \
		  $(srcdir)/include/odp/api/plat/pool_types.h \
		  $(srcdir)/include/odp/api/plat/queue_types.h \
		  $(srcdir)/include/odp/api/plat/rwlock_types.h \
		  $(srcdir)/include/odp/api/plat/rwlock_recursive_types.h \
		  $(srcdir)/include/odp/api/plat/schedule_types.h \
		  $(srcdir)/include/odp/api/plat/shared_memory_types.h \
		  $(srcdir)/include/odp/api/plat/spinlock_types.h \
		  $(srcdir)/include/odp/api/plat/spinlock_recursive_types.h \
		  $(srcdir)/include/odp/api/plat/strong_types.h \
		  $(srcdir)/include/odp/api/plat/thread_types.h \
		  $(srcdir)/include/odp/api/plat/thrmask_types.h \
		  $(srcdir)/include/odp/api/plat/ticketlock_types.h \
		  $(srcdir)/include/odp/api/plat/time_types.h \
		  $(srcdir)/include/odp/api/plat/timer_types.h \
		  $(srcdir)/include/odp/api/plat/traffic_mngr_types.h \
		  $(srcdir)/include/odp/api/plat/version_types.h \
          $(srcdir)/include/odp/api/plat/stream_packetizer_types.h \
          $(srcdir)/include/odp/api/plat/socket_io_types.h

noinst_HEADERS = \
		  ${srcdir}/include/odp_align_internal.h \
		  ${srcdir}/include/odp_atomic_internal.h \
		  ${srcdir}/include/odp_buffer_inlines.h \
		  ${srcdir}/include/odp_buffer_internal.h \
		  ${srcdir}/include/odp_classification_datamodel.h \
		  ${srcdir}/include/odp_classification_inlines.h \
		  ${srcdir}/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_config_internal.h \
		  ${srcdir}/include/odp_crypto_internal.h \
          ${srcdir}/include/odp_epoll_internal.h \
		  ${srcdir}/include/odp_debug_internal.h \
          ${srcdir}/include/odp_fileio_internal.h \
		  ${srcdir}/include/odp_forward_typedefs_internal.h \
		  ${srcdir}/include/odp_internal.h \
		  ${srcdir}/include/odp_name_table_internal.h \
		  ${srcdir}/include/odp_packet_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${srcdir}/include/odp_packet_io_ipc_internal.h \
		  ${srcdir}/include/odp_packet_io_queue.h \
		  ${srcdir}/include/odp_packet_io_ring_internal.h \
		  ${srcdir}/include/odp_packet_netmap.h \
		  ${srcdir}/include/odp_packet_dpdk.h \
		  ${srcdir}/include/odp_packet_socket.h \
		  ${srcdir}/include/odp_packet_tap.h \
		  ${srcdir}/include/odp_pkt_queue_internal.h \
		  ${srcdir}/include/odp_pool_internal.h \
		  ${srcdir}/include/odp_posix_extensions.h \
		  ${srcdir}/include/odp_queue_internal.h \
		  ${srcdir}/include/odp_schedule_if.h \
		  ${srcdir}/include/odp_schedule_internal.h \
          ${srcdir}/include/odp_socket_io_internal.h \
          ${srcdir}/include/odp_socket_io_queue.h \
          ${srcdir}/include/odp_stream_packetizer_internal.h \
		  ${srcdir}/include/odp_schedule_ordered_internal.h \
		  ${srcdir}/include/odp_sorted_list_internal.h \
		  ${srcdir}/include/odp_shm_internal.h \
		  ${srcdir}/include/odp_timer_internal.h \
		  ${srcdir}/include/odp_timer_wheel_internal.h \
		  ${srcdir}/include/odp_traffic_mngr_internal.h \
		  ${srcdir}/include/protocols/eth.h \
		  ${srcdir}/include/protocols/ip.h \
		  ${srcdir}/include/protocols/ipsec.h \
		  ${srcdir}/include/protocols/tcp.h \
		  ${srcdir}/include/protocols/udp.h \
		  ${srcdir}/Makefile.inc

__LIB__libodp_linux_la_SOURCES = \
			   odp_atomic.c \
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_classification.c \
			   odp_cpu.c \
			   odp_cpumask.c \
			   odp_cpumask_task.c \
			   odp_crypto.c \
			   odp_errno.c \
			   odp_event.c \
			   odp_hash.c \
			   odp_init.c \
			   odp_impl.c \
			   odp_name_table.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   pktio/ethtool.c \
			   pktio/io_ops.c \
			   pktio/ipc.c \
			   pktio/pktio_common.c \
			   pktio/loop.c \
			   pktio/netmap.c \
			   pktio/dpdk.c \
			   pktio/socket.c \
			   pktio/socket_mmap.c \
			   pktio/sysfs.c \
			   pktio/tap.c \
			   pktio/ring.c \
			   odp_pkt_queue.c \
			   odp_pool.c \
			   odp_queue.c \
			   odp_rwlock.c \
			   odp_rwlock_recursive.c \
			   odp_schedule.c \
			   odp_schedule_if.c \
			   odp_schedule_ordered.c \
			   odp_schedule_sp.c \
			   odp_shared_memory.c \
			   odp_sorted_list.c \
			   odp_spinlock.c \
			   odp_spinlock_recursive.c \
			   odp_system_info.c \
			   odp_thread.c \
			   odp_thrmask.c \
			   odp_ticketlock.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_timer_wheel.c \
			   odp_traffic_mngr.c \
			   odp_version.c \
			   odp_weak.c \
			   arch/@ARCH_DIR@/odp_cpu_arch.c \
			   arch/@ARCH_DIR@/odp_sysinfo_parse.c

EXTRA_DIST = \
	     arch/default/odp/api/cpu_arch.h \
	     arch/default/odp_cpu_arch.c \
	     arch/default/odp_sysinfo_parse.c \
	     arch/mips64/odp/api/cpu_arch.h \
	     arch/mips64/odp_cpu_arch.c \
	     arch/mips64/odp_sysinfo_parse.c \
	     arch/powerpc/odp/api/cpu_arch.h \
	     arch/powerpc/odp_cpu_arch.c \
	     arch/powerpc/odp_sysinfo_parse.c \
	     arch/x86/odp/api/cpu_arch.h \
	     arch/x86/odp_cpu_arch.c \
	     arch/x86/odp_sysinfo_parse.c \
	     arch/arm/odp/api/cpu_arch.h \
	     arch/arm/odp_cpu_arch.c \
	     arch/arm/odp_sysinfo_parse.c

if HAVE_PCAP
__LIB__libodp_linux_la_SOURCES += pktio/pcap.c
endif
