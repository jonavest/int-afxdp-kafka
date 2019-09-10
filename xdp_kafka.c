// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

#include <asm/barrier.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/compiler.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <librdkafka/rdkafka.h>
#include "lut.h"
#include "itoa.h"

#include "libbpf.h"
#include "xsk.h"
#include <bpf/bpf.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64

#define MAX_SOCKS 8
//#define DEBUG_HEXDUMP
//#define DEBUG_INTDUMP
//#define KAFKA_ENABLE
#define PARSER_ENABLE

typedef __u64 u64;
typedef __u32 u32;

static unsigned long prev_time;

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "enp101s0f0";
static int opt_ifindex;
static int opt_queue;
static int opt_poll;
static int opt_interval = 1;
static u32 opt_xdp_bind_flags;
static __u32 prog_id;
static volatile int kafka_rx_ok = 0;
static volatile int kafka_rx_err = 0;
static volatile int kafka_prev_rx_ok = 0;
static volatile int kafka_prev_rx_err = 0;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];

#ifdef KAFKA_ENABLE
rd_kafka_t *kafka_rd;
rd_kafka_topic_t *kafka_rkt;
rd_kafka_conf_t *kafka_conf;
char kafka_errstr[512];
#endif

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

void itoa_fast(char * s, int d) {
        if (d < 0) {
                d = -d;
                *(s++) = '-';
        }
        int rem = d % 10;
        int count = 0;
        if (d != 0) {
                while(d > 0) {
                        *(s++) = rem + '0';
                        d = d / 10;
                        rem = d % 10;
                        count++;
                }
        } else {
                *(s++) = '0';
                count++;
        }
        reverse((s - count), count);
        *(s) = '\0';
}

void reverse(char * s, int len) {
        int pos = 0;
        len--;
        while(pos < len) {
                char c = *(s + len);
                *(s + len) = *(s + pos);
                *(s + pos) = c;
                pos++;
                len--;
        }
}

static void dump_stats(void)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;
	char *fmt = "%-15s %'-11.0f %'-11lu\n";

	prev_time = now;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		double rx_pps, tx_pps;
		#ifdef KAFKA_ENABLE
		double kafka_pps;
		kafka_pps = (kafka_rx_ok - kafka_prev_rx_ok) *
			 1000000000. / dt;
		#endif

		rx_pps = (xsks[i]->rx_npkts - xsks[i]->prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->tx_npkts - xsks[i]->prev_tx_npkts) *
			 1000000000. / dt;

		/*
		printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
		       dt / 1000000000.);
		printf(fmt, "rx", rx_pps, xsks[i]->rx_npkts);
		printf(fmt, "tx", tx_pps, xsks[i]->tx_npkts);
		*/
		#ifndef KAFKA_ENABLE
		printf("%.2f\n", rx_pps);
		#else
		printf("%.2f\n", kafka_pps);
		#endif

		xsks[i]->prev_rx_npkts = xsks[i]->rx_npkts;
		xsks[i]->prev_tx_npkts = xsks[i]->tx_npkts;
		kafka_prev_rx_ok = kafka_rx_ok;
	}
}

static void *poller(void *arg)
{
	(void)arg;
	for (;;) {
		sleep(opt_interval);
		dump_stats();
	}

	return NULL;
}

static void remove_xdp_program(void)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(opt_ifindex, &curr_prog_id, opt_xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(EXIT_FAILURE);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
}

static void int_exit(int sig)
{
	struct xsk_umem *umem = xsks[0]->umem->umem;

	(void)sig;

	dump_stats();
	xsk_socket__delete(xsks[0]->xsk);
	(void)xsk_umem__delete(umem);
	remove_xdp_program();

	exit(EXIT_SUCCESS);
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));
	dump_stats();
	remove_xdp_program();
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
						 __LINE__)
#ifdef DEBUG_HEXDUMP
static void hex_dump(void *pkt, size_t length, u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}
#endif

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	int ret;
	u32 idx;
	int i;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;
	ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
				 &xsk->rx, &xsk->tx, &cfg);
	if (ret)
		exit_with_error(-ret);

	ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, opt_xdp_flags);
	if (ret)
		exit_with_error(-ret);

	ret = xsk_ring_prod__reserve(&xsk->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		exit_with_error(-ret);
	for (i = 0;
	     i < XSK_RING_PROD__DEFAULT_NUM_DESCS *
		     XSK_UMEM__DEFAULT_FRAME_SIZE;
	     i += XSK_UMEM__DEFAULT_FRAME_SIZE)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = i;
	xsk_ring_prod__submit(&xsk->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk;
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_only(struct xsk_socket_info *xsk)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	kick_tx(xsk);

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
		xsk->tx_npkts += rcvd;
	}
}

#define INT_SWITCHID 1 << 7
#define INT_INPORT 1 << 6
#define INT_HOP_LATENCY 1 << 5
#define INT_QUEUE 1 << 4
#define INT_INGRESS_TS 1 << 3
#define INT_EGRESS_TS 1 << 2
#define INT_XG_PORT 1 << 1
#define INT_TX_UTIL 1

#ifdef KAFKA_ENABLE
static void kafka_push_msg(const char * key, char * buf, int len) {
retry:
	if (rd_kafka_produce(kafka_rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, buf, len, NULL, 0, NULL) == -1) {
		if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
			rd_kafka_poll(kafka_rd, 1000);
			goto retry;
		}
		else
		{
			fprintf(stderr, "%% Failed to produce to topic: %s\n", rd_kafka_err2str(rd_kafka_last_error()));
		}
	}
}
#endif

#ifdef PARSER_ENABLE
#define BIT_ON(X,Y) (X & Y) == Y
#define PUSH_U32(X,Y) if(BIT_ON(int_mask, X)) { strcpy(bp, Y ":"); bp += sizeof(Y); itoa_fast(bp, htonl(*((uint32_t *)ptr))); strcat(bp, ","); bp += strlen(bp); ptr += 4; }
static void send_to_kafka(void *pkt, size_t length, u64 addr) {

	int i;
	void *ptr = pkt;
	ptr += 14; // Skip src, dst and etype
	ptr += 20; // We don't care about IP

	ptr += 2; 
	uint16_t port = ntohs(*((uint16_t *)ptr));
	if(port != 4321) return; // Let's make sure dport = 4321

	ptr += 16; //Telemetry header

	//Format: srcip,dstip,srcport,dstport
	char buffer[1024];
	char * bp = buffer;
	bzero(buffer, sizeof(buffer));

	// TODO: Inner header processing might be smarter
	ptr += 14; // Inner Ethernet

	// IP Address
	for (i = 22; i < 26; i++)
		strcat(buffer, IP_LUT[*((uint8_t *)ptr + i)]);
	bp = buffer + strlen(buffer) - 1;
	bp[0] = 0;
	strcat(buffer, ",");
	for (i = 18; i < 22; i++)
		strcat(buffer, IP_LUT[*((uint8_t *)ptr + i)]);
	bp = buffer + strlen(buffer) - 1;
	bp[0] = 0;
	strcat(buffer, ",");
	bp++;

	ptr += 26; // Inner IP

	itoa_fast(bp, htons(*((uint16_t *)ptr)));
	strcat(bp, ",");
	bp += strlen(bp);
	itoa_fast(bp, htons(*((uint16_t *)ptr + 1)));
	strcat(bp, ",");
	bp += strlen(bp);
	ptr += 20; // Inner TCP 
	ptr += 4; // Shim 

	ptr += 2; // verrep,cem,rsvd
	uint8_t int_count = *((uint8_t *)ptr);
	ptr += 2;
	uint8_t int_mask = *((uint8_t *)ptr);
	ptr += 4; // Move to first value

	for(i = 0; i < int_count; i++) {
		PUSH_U32(INT_SWITCHID, "switchid");
		PUSH_U32(INT_INPORT, "inport");
		PUSH_U32(INT_HOP_LATENCY, "hop-latency");
		PUSH_U32(INT_QUEUE, "queue");
		PUSH_U32(INT_INGRESS_TS, "ingress-ts");
		PUSH_U32(INT_EGRESS_TS, "egress-ts");
		PUSH_U32(INT_XG_PORT, "xg-port");
		PUSH_U32(INT_TX_UTIL, "tx-util");
	}

	#ifdef KAFKA_ENABLE
	kafka_push_msg("int", buffer, strlen(buffer));
	#endif

	buffer[strlen(buffer) - 1] = 0;

	#ifdef DEBUG_INTDUMP
	printf("Port: %d\n", port);
	printf("INT Header Count: %d\n", int_count);
	printf("INT Mask: %x\n", int_mask);
	printf("Kafka Message: %s\n", buffer);
	#endif
}
#endif

static void rx_drop(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, i;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		#if defined PARSER_ENABLE || defined DEBUG_HEXDUMP
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		#endif

		#ifdef PARSER_ENABLE
		send_to_kafka(pkt, len, addr);
		#endif
		#ifdef DEBUG_HEXDUMP
		hex_dump(pkt, len, addr);
		#endif
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}

	#ifdef KAFKA_ENABLE
	rd_kafka_poll(kafka_rd, 0);
	#endif

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->rx_npkts += rcvd;
}

static void rx_drop_all(void)
{
	struct pollfd fds[MAX_SOCKS + 1];
	int i, ret, timeout, nfds = 1;

	memset(fds, 0, sizeof(fds));

	for (i = 0; i < num_socks; i++) {
		fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
		fds[i].events = POLLIN;
		timeout = 1000; /* 1sn */
	}

	for (;;) {
		if (opt_poll) {
			ret = poll(fds, nfds, timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++)
			rx_drop(xsks[i]);
	}
}

#ifdef KAFKA_ENABLE
static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *msg, void *opaque) {
	if (msg->err) {
		kafka_rx_err += 1;
		#ifdef DEBUG_INTDUMP
		fprintf(stderr, "%% Message delivery failed: %s\n", rd_kafka_err2str(msg->err));
		#endif
	} else {
		kafka_rx_ok += 1;
		#ifdef DEBUG_INTDUMP
		fprintf(stderr, "%% Message delivered (%zd bytes, " "partition %"PRId32")\n", msg->len, msg->partition);
		#endif
	}
}
#endif

#define KAFKA_CONF(X,Y) if(rd_kafka_conf_set(kafka_conf, X, Y, kafka_errstr, sizeof(kafka_errstr)) != RD_KAFKA_CONF_OK) { fprintf(stderr, "Could not configure Kafka: %s\n", kafka_errstr); exit(EXIT_FAILURE); }
int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	pthread_t pt;
	void *bufs;
	int ret;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) { fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	opt_if = argv[1];

	#ifdef KAFKA_ENABLE
	//Kafka configuration
	kafka_conf = rd_kafka_conf_new();
	KAFKA_CONF("bootstrap.servers", "127.0.0.1:9092");
	KAFKA_CONF("queue.buffering.max.ms", "100");
	KAFKA_CONF("batch.num.messages", "500000");
	KAFKA_CONF("message.send.max.retries", "3");
	KAFKA_CONF("retry.backoff.ms", "500");

	KAFKA_CONF("queued.min.messages", "1000000");
	KAFKA_CONF("session.timeout.ms", "6000");
	rd_kafka_conf_set_dr_msg_cb(kafka_conf, dr_msg_cb);

	kafka_rd = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_conf, kafka_errstr, sizeof(kafka_errstr));
	if (!kafka_rd) {
		fprintf(stderr, "Could not configure Kafka producer: %s\n", kafka_errstr);
		exit(EXIT_FAILURE);
	}

	kafka_rkt = rd_kafka_topic_new(kafka_rd, "headers", NULL);
	if (!kafka_rkt) {
		fprintf(stderr, "Could not configure Kafka topic: %s\n", kafka_errstr);
		exit(EXIT_FAILURE);
	}
	#endif

	opt_ifindex = if_nametoindex(opt_if);
	printf("Ifindex %d\n", opt_ifindex);

	ret = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
			     NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (ret)
		exit_with_error(ret);

       /* Create sockets... */
	umem = xsk_configure_umem(bufs,
				  NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	xsks[num_socks++] = xsk_configure_socket(umem);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	ret = pthread_create(&pt, NULL, poller, NULL);
	if (ret)
		exit_with_error(ret);

	prev_time = get_nsecs();

	rx_drop_all();

	return 0;
}
