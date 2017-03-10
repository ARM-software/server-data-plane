include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

PLAT_CFLAGS  =
if ARCH_X86
PLAT_CFLAGS  += -msse4.2
endif

if DPDK_HEADER_HACK
PLAT_CFLAGS += -include /usr/include/dpdk/rte_config.h
else
PLAT_CFLAGS += -include $(SDK_INSTALL_PATH)/include/rte_config.h
endif

AM_CFLAGS +=  $(PLAT_CFLAGS)
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -Iinclude
AM_CFLAGS +=  -Iofp/include/api
AM_CFLAGS +=  -Iofp/include
AM_CFLAGS +=  -DINET -DINET6
AM_CFLAGS +=  -DODP_PKTIO_DPDK

if SHARED_DPDK
DPDK_LIBS = -Wl,--no-as-needed,-ldpdk,--as-needed -ldl -lm -lpcap
else
DPDK_LIBS = -l:libdpdk.a -ldl -lm -lpcap
endif
LIBS += $(DPDK_LIBS)

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
		  $(builddir)/include/odp/api/inlines.h \
		  $(srcdir)/include/odp/api/packet_flags.h \
		  $(srcdir)/include/odp/api/packet_flags_inlines.h \
		  $(srcdir)/include/odp/api/packet.h \
		  $(srcdir)/include/odp/api/packet_inlines.h \
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
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  ${srcdir}/include/odp_buffer_inlines.h \
		  ${srcdir}/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_config_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_forward_typedefs_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${srcdir}/include/odp_packet_dpdk.h \
		  ${srcdir}/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_name_table_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ipc_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_queue.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pkt_queue_internal.h \
		  ${srcdir}/include/odp_pool_internal.h \
		  ${srcdir}/include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${srcdir}/include/odp_schedule_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_ordered_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_sorted_list_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_shm_internal.h \
		  ${srcdir}/include/odp_time_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_wheel_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_traffic_mngr_internal.h \
		  ${srcdir}/include/protocols/eth.h \
		  ${srcdir}/include/protocols/ip.h \
		  ${srcdir}/include/protocols/ipsec.h \
		  ${srcdir}/include/protocols/tcp.h \
		  ${srcdir}/include/protocols/udp.h \
          ${top_srcdir}/platform/linux-generic/include/odp_epoll_internal.h \
          ${top_srcdir}/platform/linux-generic/include/odp_fileio_internal.h \
          ${top_srcdir}/platform/linux-generic/include/odp_socket_io_internal.h \
          ${top_srcdir}/platform/linux-generic/include/odp_socket_io_queue.h \
          ${top_srcdir}/platform/linux-generic/include/odp_stream_packetizer_internal.h \
          ${srcdir}/include/odp_chained_buffer_internal.h \
          ${srcdir}/include/odp_linux_helper_internal.h \
		  ${srcdir}/Makefile.inc \
          ${srcdir}/ofp/include/api/ofp_cli.h \
          ${srcdir}/ofp/include/api/ofp_config.h \
          ${srcdir}/ofp/include/api/ofp_debug.h \
          ${srcdir}/ofp/include/api/ofp_errno.h \
          ${srcdir}/ofp/include/api/ofp_ethernet.h \
          ${srcdir}/ofp/include/api/ofp.h \
          ${srcdir}/ofp/include/api/ofp_hook.h \
          ${srcdir}/ofp/include/api/ofp_icmp6.h \
          ${srcdir}/ofp/include/api/ofp_icmp.h \
          ${srcdir}/ofp/include/api/ofp_ifnet.h \
          ${srcdir}/ofp/include/api/ofp_if_vlan.h \
          ${srcdir}/ofp/include/api/ofp_in6.h \
          ${srcdir}/ofp/include/api/ofp_in.h \
          ${srcdir}/ofp/include/api/ofp_init.h \
          ${srcdir}/ofp/include/api/ofp_ioctl.h \
          ${srcdir}/ofp/include/api/ofp_ip6.h \
          ${srcdir}/ofp/include/api/ofp_ip.h \
          ${srcdir}/ofp/include/api/ofp_ip_var.h \
          ${srcdir}/ofp/include/api/ofp_log.h \
          ${srcdir}/ofp/include/api/ofp_pkt_processing.h \
          ${srcdir}/ofp/include/api/ofp_portconf.h \
          ${srcdir}/ofp/include/api/ofp_queue.h \
          ${srcdir}/ofp/include/api/ofp_route_arp.h \
          ${srcdir}/ofp/include/api/ofp_socket.h \
          ${srcdir}/ofp/include/api/ofp_socket_types.h \
          ${srcdir}/ofp/include/api/ofp_stat.h \
          ${srcdir}/ofp/include/api/ofp_sysctl.h \
          ${srcdir}/ofp/include/api/ofp_tcp.h \
          ${srcdir}/ofp/include/api/ofp_timer.h \
          ${srcdir}/ofp/include/api/ofp_types.h \
          ${srcdir}/ofp/include/api/ofp_udp.h \
          ${srcdir}/ofp/include/api/ofp_utils.h \
          ${srcdir}/ofp/include/ofpi_arp.h \
          ${srcdir}/ofp/include/ofpi_avl.h \
          ${srcdir}/ofp/include/ofpi_callout.h \
          ${srcdir}/ofp/include/ofpi_cli.h \
          ${srcdir}/ofp/include/ofpi_config.h \
          ${srcdir}/ofp/include/ofpi_debug.h \
          ${srcdir}/ofp/include/ofpi_domain.h \
          ${srcdir}/ofp/include/ofpi_errno.h \
          ${srcdir}/ofp/include/ofpi_ethernet.h \
          ${srcdir}/ofp/include/ofpi_gre.h \
          ${srcdir}/ofp/include/ofpi.h \
          ${srcdir}/ofp/include/ofpi_hash.h \
          ${srcdir}/ofp/include/ofpi_hook.h \
          ${srcdir}/ofp/include/ofpi_icmp6.h \
          ${srcdir}/ofp/include/ofpi_icmp.h \
          ${srcdir}/ofp/include/ofpi_if_arp.h \
          ${srcdir}/ofp/include/ofpi_if_gre.h \
          ${srcdir}/ofp/include/ofpi_ifnet.h \
          ${srcdir}/ofp/include/ofpi_if_vlan.h \
          ${srcdir}/ofp/include/ofpi_if_vxlan.h \
          ${srcdir}/ofp/include/ofpi_igmp.h \
          ${srcdir}/ofp/include/ofpi_igmp_var.h \
          ${srcdir}/ofp/include/ofpi_in6.h \
          ${srcdir}/ofp/include/ofpi_in6_pcb.h \
          ${srcdir}/ofp/include/ofpi_inet.h \
          ${srcdir}/ofp/include/ofpi_in.h \
          ${srcdir}/ofp/include/ofpi_init.h \
          ${srcdir}/ofp/include/ofpi_in_pcb.h \
          ${srcdir}/ofp/include/ofpi_in_var.h \
          ${srcdir}/ofp/include/ofpi_ioctl.h \
          ${srcdir}/ofp/include/ofpi_ip6.h \
          ${srcdir}/ofp/include/ofpi_ip6protosw.h \
          ${srcdir}/ofp/include/ofpi_ip6_var.h \
          ${srcdir}/ofp/include/ofpi_ip.h \
          ${srcdir}/ofp/include/ofpi_ip_var.h \
          ${srcdir}/ofp/include/ofpi_log.h \
          ${srcdir}/ofp/include/ofpi_md5.h \
          ${srcdir}/ofp/include/ofpi_netlink.h \
          ${srcdir}/ofp/include/ofpi_pkt_processing.h \
          ${srcdir}/ofp/include/ofpi_portconf.h \
          ${srcdir}/ofp/include/ofpi_protosw.h \
          ${srcdir}/ofp/include/ofpi_queue.h \
          ${srcdir}/ofp/include/ofpi_reass.h \
          ${srcdir}/ofp/include/ofpi_route.h \
          ${srcdir}/ofp/include/ofpi_rt_lookup.h \
          ${srcdir}/ofp/include/ofpi_shared_mem.h \
          ${srcdir}/ofp/include/ofpi_sockbuf.h \
          ${srcdir}/ofp/include/ofpi_socket.h \
          ${srcdir}/ofp/include/ofpi_socketvar.h \
          ${srcdir}/ofp/include/ofpi_sockopt.h \
          ${srcdir}/ofp/include/ofpi_sockstate.h \
          ${srcdir}/ofp/include/ofpi_stat.h \
          ${srcdir}/ofp/include/ofpi_syscalls.h \
          ${srcdir}/ofp/include/ofpi_sysctl.h \
          ${srcdir}/ofp/include/ofpi_systm.h \
          ${srcdir}/ofp/include/ofpi_tcp6_var.h \
          ${srcdir}/ofp/include/ofpi_tcp_fsm.h \
          ${srcdir}/ofp/include/ofpi_tcp.h \
          ${srcdir}/ofp/include/ofpi_tcp_offload.h \
          ${srcdir}/ofp/include/ofpi_tcp_seq.h \
          ${srcdir}/ofp/include/ofpi_tcp_shm.h \
          ${srcdir}/ofp/include/ofpi_tcp_syncache.h \
          ${srcdir}/ofp/include/ofpi_tcp_timer.h \
          ${srcdir}/ofp/include/ofpi_tcp_var.h \
          ${srcdir}/ofp/include/ofpi_timer.h \
          ${srcdir}/ofp/include/ofpi_tree.h \
          ${srcdir}/ofp/include/ofpi_udp6_var.h \
          ${srcdir}/ofp/include/ofpi_udp.h \
          ${srcdir}/ofp/include/ofpi_udp_var.h \
          ${srcdir}/ofp/include/ofpi_uma.h \
          ${srcdir}/ofp/include/ofpi_util.h \
          ${srcdir}/ofp/include/ofpi_vnet.h \
          ${srcdir}/ofp/include/ofpi_vxlan.h 

__LIB__libodp_dpdk_la_SOURCES = \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   ../linux-generic/odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   ../linux-generic/odp_cpumask_task.c \
			   ../linux-generic/odp_crypto.c \
			   odp_errno.c \
			   ../linux-generic/odp_event.c \
			   ../linux-generic/odp_hash.c \
			   odp_init.c \
			   ../linux-generic/odp_impl.c \
			   ../linux-generic/odp_name_table.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   odp_packet_flags.c \
			   ../linux-generic/odp_packet_io.c \
			   ../linux-generic/pktio/loop.c \
			   ../linux-generic/odp_pkt_queue.c \
			   odp_pool.c \
			   ../linux-generic/odp_queue.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   odp_schedule.c \
			   ../linux-generic/odp_schedule_if.c \
			   ../linux-generic/odp_schedule_ordered.c \
			   ../linux-generic/odp_shared_memory.c \
			   ../linux-generic/odp_sorted_list.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   odp_std_clib.c \
			   ../linux-generic/odp_system_info.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   odp_time.c \
			   ../linux-generic/odp_timer.c \
			   ../linux-generic/odp_timer_wheel.c \
			   ../linux-generic/odp_traffic_mngr.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
               odp_socket_io.c \
               odp_chained_buffer.c \
               odp_stream_packetizer.c \
               ../linux-generic/odp_pthreadlock.c \
               ../linux-generic/odp_epoll.c \
               odp_fileio.c \
               odp_linux_helper.c \
               ofp/src/cli/ofp_cli.c \
               ofp/src/cli/ofp_cli_alias.c \
               ofp/src/cli/ofp_cli_arp.c \
               ofp/src/cli/ofp_cli_debug.c \
               ofp/src/cli/ofp_cli_ifconfig.c \
               ofp/src/cli/ofp_cli_log.c \
               ofp/src/cli/ofp_cli_route.c \
               ofp/src/cli/ofp_cli_stat.c \
               ofp/src/cli/ofp_cli_sysctl.c \
               ofp/src/ofp_arp.c \
               ofp/src/ofp_avl.c \
               ofp/src/ofp_debug.c \
               ofp/src/ofp_debug_pcap.c \
               ofp/src/ofp_debug_print.c \
               ofp/src/ofp_errno.c \
               ofp/src/ofp_gre.c \
               ofp/src/ofp_hash.c \
               ofp/src/ofp_hook.c \
               ofp/src/ofp_icmp.c \
               ofp/src/ofp_ifnet.c \
               ofp/src/ofp_igmp.c \
               ofp/src/ofp_in.c \
               ofp/src/ofp_in_cksum.c \
               ofp/src/ofp_inet.c \
               ofp/src/ofp_init.c \
               ofp/src/ofp_in_mcast.c \
               ofp/src/ofp_in_pcb.c \
               ofp/src/ofp_in_proto.c \
               ofp/src/ofp_ip_init.c \
               ofp/src/ofp_log.c \
               ofp/src/ofp_md5c.c \
               ofp/src/ofp_pkt_processing.c \
               ofp/src/ofp_pkt_send_burst.c \
               ofp/src/ofp_portconf.c \
               ofp/src/ofp_reass.c \
               ofp/src/ofp_route.c \
               ofp/src/ofp_rt_lookup.c \
               ofp/src/ofp_shared_mem.c \
               ofp/src/ofp_stat.c \
               ofp/src/ofp_subr_hash.c \
               ofp/src/ofp_syscalls.c \
               ofp/src/ofp_sysctl.c \
               ofp/src/ofp_sys_socket.c \
               ofp/src/ofp_tcp_input.c \
               ofp/src/ofp_tcp_output.c \
               ofp/src/ofp_tcp_reass.c \
               ofp/src/ofp_tcp_sack.c \
               ofp/src/ofp_tcp_subr.c \
               ofp/src/ofp_tcp_syncache.c \
               ofp/src/ofp_tcp_timer.c \
               ofp/src/ofp_tcp_timewait.c \
               ofp/src/ofp_tcp_usrreq.c \
               ofp/src/ofp_timer.c \
               ofp/src/ofp_udp_usrreq.c \
               ofp/src/ofp_uipc_domain.c \
               ofp/src/ofp_uipc_sockbuf.c \
               ofp/src/ofp_uipc_socket.c \
               ofp/src/ofp_uma.c \
               ofp/src/ofp_util.c \
               ofp/src/ofp_vxlan.c \
               ofp/src/ofp_ip6_init.c \
               ofp/src/ofp_in6_proto.c \
               ofp/src/ofp_in6.c \
               ofp/src/ofp_in6_pcb.c \
               ofp/src/ofp_in6_cksum.c \
               ofp/src/ofp_udp6_usrreq.c \
               ofp/src/ofp_icmp6.c \
               ofp/src/ofp_nd6.c \
			   arch/@ARCH_DIR@/odp_cpu_arch.c \
			   arch/@ARCH_DIR@/odp_sysinfo_parse.c
