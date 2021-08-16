/*
 * Copyright (c) 2014-2015 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>

#include <fstrm.h>
#include <ldns/ldns.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include "dnstap.pb/dnstap.pb-c.h"

#include "fstrm/libmy/argv.h"
#include "fstrm/libmy/my_alloc.h"
#include "fstrm/libmy/print_string.h"

#include "liblogfaf/src/liblogfaf.h"

/* From our host2str.c. */
ldns_status my_ldns_pktheader2buffer_str(ldns_buffer *, const ldns_pkt *);
ldns_status my_ldns_pkt2buffer_str_fmt(ldns_buffer *, const ldns_output_format *, const ldns_pkt *);

#if HAVE_DECL_FFLUSH_UNLOCKED
# define fflush fflush_unlocked
#endif

#if HAVE_DECL_FREAD_UNLOCKED
# define fread fread_unlocked
#endif

#if HAVE_DECL_FWRITE_UNLOCKED
# define fwrite fwrite_unlocked
#endif

struct capture;
struct capture_args;
struct conn;

typedef enum {
	CONN_STATE_READING_CONTROL_READY,
	CONN_STATE_READING_CONTROL_START,
	CONN_STATE_READING_DATA,
	CONN_STATE_STOPPED,
} conn_state;

typedef enum conn_verbosity {
	CONN_CRITICAL		= 0,
	CONN_ERROR		= 1,
	CONN_WARNING		= 2,
	CONN_INFO		= 3,
	CONN_DEBUG		= 4,
	CONN_TRACE		= 5,
} conn_verbosity;

struct conn {
	struct capture		*ctx;
	conn_state		state;
	uint32_t		len_frame_payload;
	uint32_t		len_frame_total;
	size_t			len_buf;
	size_t			bytes_read;
	size_t			bytes_skip;
	size_t			count_read;
	struct bufferevent	*bev;
	struct evbuffer		*ev_input;
	struct evbuffer		*ev_output;
	struct fstrm_control	*control;
};

struct capture {
	struct capture_args	*args;

	struct sockaddr_storage	ss;
	socklen_t		ss_len;
	evutil_socket_t		listen_fd;
	struct event_base	*ev_base;
	struct evconnlistener	*ev_connlistener;
	struct event		*ev_sighup;

	size_t			bytes_written;
	size_t			count_written;
	size_t			capture_highwater;
	int			remaining_connections;

};

struct capture_args {
	bool			help;
	int			debug;
	char			*str_content_type;
	char			*str_read_tcp_address;
	char			*str_read_tcp_port;
	int			buffer_size;
	int			count_connections;
};

struct dnstap_syslog {
	time_t			time;
	/* RFC5424 suggests that everybody be able to handle at least 2048 octets */
	char			message[2048];
};

static const char g_dnstap_content_type[] = "protobuf:dnstap.Dnstap";

static struct capture		g_program_ctx;
static struct capture_args	g_program_args = {
	.str_content_type = g_dnstap_content_type, 
};

static argv_t g_args[] = {
	{ 'h',	"help",
		ARGV_BOOL,
		&g_program_args.help,
		NULL,
		"display this help text and exit" },

	{ 'd',	"debug",
		ARGV_INCR,
		&g_program_args.debug,
		NULL,
		"increment debugging level" },

	{ 'a',	"tcp",
		ARGV_CHAR_P,
		&g_program_args.str_read_tcp_address,
		"<ADDRESS>",
		"TCP socket address to read from" },

	{ 'p',	"port",
		ARGV_CHAR_P,
		&g_program_args.str_read_tcp_port,
		"<PORT>",
		"TCP socket port to read from" },

	{ 'b',	"buffersize",
		ARGV_INT,
		&g_program_args.buffer_size,
		"<SIZE>",
		"read buffer size, in bytes (default 262144)" },

	{ 'c', "maxconns",
		ARGV_INT,
		&g_program_args.count_connections,
		"<COUNT>",
		"maximum concurrent connections allowed" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 },
};

static bool
dns_question_str(const ProtobufCBinaryData *message, char *message_buf)
{
	char *str = NULL;
	ldns_pkt *pkt = NULL;
	ldns_rr *rr = NULL;
	ldns_rdf *qname = NULL;
	ldns_rr_class qclass = 0;
	ldns_rr_type qtype = 0;
	ldns_status status;

	/* Parse the raw wire message. */
	status = ldns_wire2pkt(&pkt, message->data, message->len);
	if (status == LDNS_STATUS_OK) {
		/* Get the question RR. */
		rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);

		/* Get the question name, class, and type. */
		if (rr) {
			qname = ldns_rr_owner(rr);
			qclass = ldns_rr_get_class(rr);
			qtype = ldns_rr_get_type(rr);
		}
	}

	if (status == LDNS_STATUS_OK && rr && qname) {
		/* Print the question name. */
		strcat(message_buf, "\"");
		/* ldns_rdf_print(fp, qname); */
		str = ldns_rdf2str(qname);
		strncat(message_buf, str, LDNS_MAX_DOMAINLEN);
		strcat(message_buf, "\"");
		free(str);

		/* Print the question class. */
		str = ldns_rr_class2str(qclass);
		strcat(message_buf, " ");
		strncat(message_buf, str, 8);
		free(str);

		/* Print the question type. */
		str = ldns_rr_type2str(qtype);
		strcat(message_buf, " ");
		strncat(message_buf, str, 16);
		free(str);
	} else {
		strcat(message_buf, "? ? ?");
	}

	/* Cleanup. */
	if (pkt != NULL)
		ldns_pkt_free(pkt);

	/* Success. */
	return true;
}

static bool
ip_address_str(const ProtobufCBinaryData *ip, char *message_buf)
{
	char buf[INET6_ADDRSTRLEN] = {0};

	if (ip->len == 4) {
		/* Convert IPv4 address. */
		if (!inet_ntop(AF_INET, ip->data, buf, sizeof(buf)))
		    return false;
	} else if (ip->len == 16) {
		/* Convert IPv6 address. */
		if (!inet_ntop(AF_INET6, ip->data, buf, sizeof(buf)))
		    return false;
	} else {
		/* Unknown address family. */
		return false;
	}

	/* Print the presentation form of the IP address. */
	strncat(message_buf, buf, INET6_ADDRSTRLEN);

	/* Success. */
	return true;
}

static bool
timestamp_str(uint64_t timestamp_sec, uint32_t timestamp_nsec, char *message_buf)
{
	static const char *fmt = "%F %H:%M:%S";

	char buf[100] = {0};
	struct tm tm;
	time_t t = (time_t) timestamp_sec;

	/* Convert arguments to broken-down 'struct tm'. */
	if (!gmtime_r(&t, &tm))
		return false;

	/* Format 'tm' into 'buf'. */
	if (strftime(buf, sizeof(buf), fmt, &tm) <= 0)
		return false;

	/* Print the timestamp. */
	strncat(message_buf, buf, 100);

	char timestamp_nsec_str[8] = {0};

	snprintf(timestamp_nsec_str, 7, ".%06u", timestamp_nsec / 1000);

	strncat(message_buf, timestamp_nsec_str, 7);

	/* Success. */
	return true;
}

static bool
dnstap_message_quiet_to_dnstap_syslog(const Dnstap__Message *m, struct dnstap_syslog *dnstap_syslog_buf)
{
	bool is_query = false;
	bool print_query_address = false;

	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
		is_query = true;
		break;
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		is_query = false;
		break;
	default:
		syslog(LOG_WARNING, "[unhandled Dnstap.Message.Type]");
		return true;
	}

	/* Print timestamp. */
	if (is_query) {
		if (m->has_query_time_sec && m->has_query_time_nsec) {
			dnstap_syslog_buf->time = m->query_time_sec;
			timestamp_str(m->query_time_sec, m->query_time_nsec, dnstap_syslog_buf->message);
		} else {
			strcat(dnstap_syslog_buf->message, "??:??:??.??????");
		}
	} else {
		if (m->has_response_time_sec && m->has_response_time_nsec) {
			dnstap_syslog_buf->time = m->response_time_sec;
			timestamp_str(m->response_time_sec, m->response_time_nsec, dnstap_syslog_buf->message);
		} else {
			strcat(dnstap_syslog_buf->message, "??:??:??.??????");
		}
	}
	strcat(dnstap_syslog_buf->message, " ");

	/* Print message type mnemonic. */
	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
		strcat(dnstap_syslog_buf->message, "A");
		break;
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
		strcat(dnstap_syslog_buf->message, "C");
		break;
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
		strcat(dnstap_syslog_buf->message, "F");
		break;
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
		strcat(dnstap_syslog_buf->message, "R");
		break;
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
		strcat(dnstap_syslog_buf->message, "S");
		break;
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		strcat(dnstap_syslog_buf->message, "T");
		break;
	default:
		strcat(dnstap_syslog_buf->message, "?");
		break;
	}
	if (is_query)
		strcat(dnstap_syslog_buf->message, "Q ");
	else
		strcat(dnstap_syslog_buf->message, "R ");

	/* Print query address or response address. */
	switch (m->type) {
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
		print_query_address = true;
		break;
	default:
		print_query_address = false;
		break;
	}
	if (print_query_address) {
		if (m->has_query_address)
			ip_address_str(&m->query_address, dnstap_syslog_buf->message);
		else
			strcat(dnstap_syslog_buf->message, "MISSING_ADDRESS");
	} else {
		if (m->has_response_address)
			ip_address_str(&m->response_address, dnstap_syslog_buf->message);
		else
			strcat(dnstap_syslog_buf->message, "MISSING_ADDRESS");
	}
	strcat(dnstap_syslog_buf->message, " ");

	/* Print socket protocol. */
	if (m->has_socket_protocol) {
		const ProtobufCEnumValue *type =
			protobuf_c_enum_descriptor_get_value(
				&dnstap__socket_protocol__descriptor,
				m->socket_protocol);
		if (type)
			strcat(dnstap_syslog_buf->message, type->name);
		else
			strcat(dnstap_syslog_buf->message, "?");
	} else {
		strcat(dnstap_syslog_buf->message, "?");
	}
	strcat(dnstap_syslog_buf->message, " ");

	/* Print message size. */
	char message_size_str[14] = {0};
	if (is_query && m->has_query_message) {
		snprintf(message_size_str, 13, "%zdb ", m->query_message.len);
	} else if (!is_query && m->has_response_message) {
		snprintf(message_size_str, 13, "%zdb ", m->response_message.len);
	} else {
		strcat(dnstap_syslog_buf->message, "0b ");
	}
	strncat(dnstap_syslog_buf->message, message_size_str, 13);

	/* Print question. */
	if (is_query && m->has_query_message) {
		if (!dns_question_str(&m->query_message, dnstap_syslog_buf->message))
			return false;
	} else if (!is_query && m->has_response_message) {
		if (!dns_question_str(&m->response_message, dnstap_syslog_buf->message))
			return false;
	} else {
		strcat(dnstap_syslog_buf->message, "? ? ?");
	}

	/* Success. */
	return true;
}

static bool
syslog_dnstap_frame_quiet(const Dnstap__Dnstap *d)
{

	struct dnstap_syslog dnstap_syslog_buf = {
		.message = {0}
	};

	if (d->type == DNSTAP__DNSTAP__TYPE__MESSAGE && d->message != NULL) {
		if (dnstap_message_quiet_to_dnstap_syslog(d->message, &dnstap_syslog_buf)) {
			syslog_time(LOG_INFO, dnstap_syslog_buf.time, dnstap_syslog_buf.message);
			return true;
		}
	} else {
		syslog(LOG_WARNING, "[unhandled Dnstap.Type]");
	}

	/* Success. */
	return true;
}

static bool
print_dnstap_frame(const uint8_t *data, size_t len_data)
{
	bool rv = false;
	Dnstap__Dnstap *d = NULL;

	//fprintf(stderr, "%s: len = %zd\n", __func__, len_data);

	/* Unpack the data frame. */
	d = dnstap__dnstap__unpack(NULL, len_data, data);
	if (!d) {
		fprintf(stderr, "%s: dnstap__dnstap__unpack() failed.\n", __func__);
		goto out;
	}

	if (!syslog_dnstap_frame_quiet(d))
		goto out;

	/* Success. */
	rv = true;

out:
	/* Cleanup protobuf-c allocations. */
	if (d)
		dnstap__dnstap__free_unpacked(d, NULL);

	/* Success. */
	return rv;
}

static struct conn *
conn_init(struct capture *ctx)
{
	struct conn *conn;
	conn = my_calloc(1, sizeof(*conn));
	conn->ctx = ctx;
	conn->state = CONN_STATE_READING_CONTROL_READY;
	conn->control = fstrm_control_init();
	return conn;
}

static void
conn_destroy(struct conn **conn)
{
	if (*conn != NULL) {
		fstrm_control_destroy(&(*conn)->control);
		my_free(*conn);
	}
}

static void
conn_log(int level, struct conn *conn, const char *format, ...)
{
	if (level > conn->ctx->args->debug)
		return;
	int fd = -1;

	if (conn->bev != NULL)
		fd = (int) bufferevent_getfd(conn->bev);

	fprintf(stderr, "%s: connection fd %d: ", argv_program, fd);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fputc('\n', stderr);
}

static void
conn_log_data(int level, struct conn *conn, const void *data, size_t len, const char *format, ...)
{
	if (level > conn->ctx->args->debug)
		return;
	fprintf(stderr, "%s: connection fd %d: ", argv_program,
		(int) bufferevent_getfd(conn->bev));

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	print_string(data, len, stderr);
	fputc('\n', stderr);
}

static void
cb_close_conn(struct bufferevent *bev, short error, void *arg)
{
	struct conn *conn = (struct conn *) arg;
	struct capture *ctx = conn->ctx;

	if (error & BEV_EVENT_ERROR)
		conn_log(CONN_CRITICAL, conn, "libevent error: %s (%d)",
			 strerror(errno), errno);

	conn_log(CONN_INFO, conn, "closing (read %zd frames, %zd bytes)",
		 conn->count_read, conn->bytes_read);

	/*
	 * The BEV_OPT_CLOSE_ON_FREE flag is set on our bufferevent's, so the
	 * following call to bufferevent_free() will close the underlying
	 * socket transport.
	 */
	bufferevent_free(bev);
	conn_destroy(&conn);

	ctx->remaining_connections++;
	if (ctx->remaining_connections == 1)
		evconnlistener_enable(ctx->ev_connlistener);
}

static bool
usage(const char *msg)
{
	if (msg)
		fprintf(stderr, "%s: Usage error: %s\n", argv_program, msg);
	argv_usage(g_args, ARGV_USAGE_DEFAULT);
	argv_cleanup(g_args);
	exit(EXIT_FAILURE);
}

static bool
parse_args(const int argc, char **argv, struct capture *ctx)
{
	argv_version_string = PACKAGE_VERSION;

	if (argv_process(g_args, argc, argv) != 0)
		return false;

	/* Validate args. */
	if (g_program_args.help)
		return false;
	if (
	    g_program_args.str_read_tcp_address == NULL)
		usage("--tcp must be set");
	if (g_program_args.str_read_tcp_port == NULL)
		usage("If --tcp is set, --port must also be set");
	g_program_ctx.capture_highwater = 262144;
	if (g_program_args.buffer_size > 0)
		g_program_ctx.capture_highwater = (size_t)g_program_args.buffer_size;
	g_program_ctx.remaining_connections = -1; /* unlimited connections. */
	if (g_program_args.count_connections > 0)
		g_program_ctx.remaining_connections = (unsigned)g_program_args.count_connections;

	return true;
}

static bool
open_read_tcp(struct capture *ctx)
{
	struct sockaddr_in *sai = (struct sockaddr_in *) &ctx->ss;
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) &ctx->ss;
	uint64_t port = 0;
	char *endptr = NULL;

	/* Parse TCP listen port. */
	port = strtoul(ctx->args->str_read_tcp_port, &endptr, 0);
	if (*endptr != '\0' || port > UINT16_MAX) {
		usage("Failed to parse TCP listen port");
		return false;
	}

	if (inet_pton(AF_INET, ctx->args->str_read_tcp_address, &sai->sin_addr) == 1) {
		sai->sin_family = AF_INET;
		sai->sin_port = htons(port);
		ctx->ss_len = sizeof(*sai);
	} else if (inet_pton(AF_INET6, ctx->args->str_read_tcp_address, &sai6->sin6_addr) == 1) {
		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
		ctx->ss_len = sizeof(*sai6);
	} else {
		usage("Failed to parse TCP listen address");
		return false;
	}

	/* Success. */
	fprintf(stderr, "%s: opening TCP socket [%s]:%s\n",
		argv_program, ctx->args->str_read_tcp_address, ctx->args->str_read_tcp_port);
	return true;
}

static void
process_data_frame(struct conn *conn)
{
	conn_log(CONN_TRACE, conn, "processing data frame (%u bytes)",
		 conn->len_frame_total);

	/*
	 * Peek at 'conn->len_frame_total' bytes of data from the evbuffer, and
	 * write them to the output file.
	 */

	/* Determine how many iovec's we need to read. */
	const int n_vecs = evbuffer_peek(conn->ev_input, conn->len_frame_total, NULL, NULL, 0);

	/* Allocate space for the iovec's. */
	struct evbuffer_iovec vecs[n_vecs];

	/* Retrieve the iovec's. */
	const int n = evbuffer_peek(conn->ev_input, conn->len_frame_total, NULL, vecs, n_vecs);
	assert(n == n_vecs);

	/* Write each iovec to the output file. */
	size_t bytes_read = 0;
	for (int i = 0; i < n_vecs; i++) {
		size_t len = vecs[i].iov_len;

		/* Only read up to 'conn->len_frame_total' bytes. */
		if (bytes_read + len > conn->len_frame_total)
			len = conn->len_frame_total - bytes_read;

		/* skip frame length uint32_t */
		conn_log_data(CONN_TRACE, conn, vecs[i].iov_base, 
			vecs[i].iov_len, "data frame (%zd) bytes: ", vecs[i].iov_len);

		if (!print_dnstap_frame((uint8_t *)vecs[i].iov_base + sizeof(uint32_t), 
			len - sizeof(uint32_t))) {
			fputs("Error: print_dnstap_frame() failed.\n", stderr);
		}

		bytes_read += len;
	}

	/* Check that exactly the right number of bytes were written. */
	assert(bytes_read == conn->len_frame_total);

	/* Delete the data frame from the input buffer. */
	evbuffer_drain(conn->ev_input, conn->len_frame_total);

	/* Accounting. */
	conn->count_read += 1;
	conn->bytes_read += bytes_read;
	conn->ctx->count_written += 1;
	conn->ctx->bytes_written += bytes_read;
}

static bool
send_frame(struct conn *conn, const void *data, size_t size)
{
	conn_log_data(CONN_TRACE, conn, data, size, "writing frame (%zd) bytes: ", size);

	if (bufferevent_write(conn->bev, data, size) != 0) {
		conn_log(CONN_WARNING, conn, "bufferevent_write() failed");
		return false;
	}

	return true;
}

static bool
match_content_type(struct conn *conn)
{
	fstrm_res res;

	/* Match the "Content Type" against ours. */
	res = fstrm_control_match_field_content_type(conn->control,
		(const uint8_t *) conn->ctx->args->str_content_type,
		strlen(conn->ctx->args->str_content_type));
	if (res != fstrm_res_success) {
		conn_log(CONN_WARNING, conn, "no CONTENT_TYPE matching: \"%s\"",
			 conn->ctx->args->str_content_type);
		return false;
	}

	/* Success. */
	return true;
}

static bool
write_control_frame(struct conn *conn)
{
	fstrm_res res;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);

	/* Encode the control frame. */
	res = fstrm_control_encode(conn->control,
		control_frame, &len_control_frame,
		FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		return false;

	/* Send the control frame. */
	fstrm_control_type type = 0;
	(void)fstrm_control_get_type(conn->control, &type);
	conn_log(CONN_DEBUG, conn, "sending %s (%d)",
		fstrm_control_type_to_str(type), type);
	if (!send_frame(conn, control_frame, len_control_frame))
		return false;

	/* Success. */
	return true;
}

static bool
process_control_frame_ready(struct conn *conn)
{
	fstrm_res res;

	const uint8_t *content_type = NULL;
	size_t len_content_type = 0;
	size_t n_content_type = 0;

	/* Retrieve the number of "Content Type" fields. */
	res = fstrm_control_get_num_field_content_type(conn->control, &n_content_type);
	if (res != fstrm_res_success)
		return false;

	for (size_t i = 0; i < n_content_type; i++) {
		res = fstrm_control_get_field_content_type(conn->control, i,
							   &content_type,
							   &len_content_type);
		if (res != fstrm_res_success)
			return false;
		conn_log_data(CONN_TRACE, conn,
			      content_type, len_content_type,
			      "CONTENT_TYPE [%zd/%zd] (%zd bytes): ",
			      i + 1, n_content_type, len_content_type);
	}

	/* Match the "Content Type" against ours. */
	if (!match_content_type(conn))
		return false;

	/* Setup the ACCEPT frame. */
	fstrm_control_reset(conn->control);
	res = fstrm_control_set_type(conn->control, FSTRM_CONTROL_ACCEPT);
	if (res != fstrm_res_success)
		return false;
	res = fstrm_control_add_field_content_type(conn->control,
		(const uint8_t *) conn->ctx->args->str_content_type,
		strlen(conn->ctx->args->str_content_type));
	if (res != fstrm_res_success)
		return false;
	
	/* Send the ACCEPT frame. */
	if (!write_control_frame(conn))
		return false;

	/* Success. */
	conn->state = CONN_STATE_READING_CONTROL_START;
	return true;
}

static bool
process_control_frame_start(struct conn *conn)
{
	/* Match the "Content Type" against ours. */
	if (!match_content_type(conn))
		return false;
	
	/* Success. */
	conn->state = CONN_STATE_READING_DATA;
	return true;
}

static bool
process_control_frame_stop(struct conn *conn)
{
	fstrm_res res;

	/* Setup the FINISH frame. */
	fstrm_control_reset(conn->control);
	res = fstrm_control_set_type(conn->control, FSTRM_CONTROL_FINISH);
	if (res != fstrm_res_success)
		return false;

	/* Send the FINISH frame. */
	if (!write_control_frame(conn))
		return false;
	
	conn->state = CONN_STATE_STOPPED;

	/* We return true here, which prevents the caller from closing
	 * the connection directly (with the FINISH frame still in our
	 * write buffer). The connection will be closed after the FINISH
	 * frame is written and the write callback (cb_write) is called
	 * to refill the write buffer.
	 */
	return true;
}

static bool
process_control_frame(struct conn *conn)
{
	fstrm_res res;
	fstrm_control_type type;

	/* Get the control frame type. */
	res = fstrm_control_get_type(conn->control, &type);
	if (res != fstrm_res_success)
		return false;
	conn_log(CONN_DEBUG, conn, "received %s (%u)",
		 fstrm_control_type_to_str(type), type);

	switch (conn->state) {
	case CONN_STATE_READING_CONTROL_READY: {
		if (type != FSTRM_CONTROL_READY)
			return false;
		return process_control_frame_ready(conn);
	}
	case CONN_STATE_READING_CONTROL_START: {
		if (type != FSTRM_CONTROL_START)
			return false;
		return process_control_frame_start(conn);
	}
	case CONN_STATE_READING_DATA: {
		if (type != FSTRM_CONTROL_STOP)
			return false;
		return process_control_frame_stop(conn);
	}
	default:
		return false;
	}

	/* Success. */
	return true;
}

static bool
load_control_frame(struct conn *conn)
{
	fstrm_res res;
	uint8_t *control_frame = NULL;

	/* Check if the frame is too big. */
	if (conn->len_frame_total >= FSTRM_CONTROL_FRAME_LENGTH_MAX) {
		/* Malformed. */
		return false;
	}

	/* Get a pointer to the full, linearized control frame. */
	control_frame = evbuffer_pullup(conn->ev_input, conn->len_frame_total);
	if (!control_frame) {
		/* Malformed. */
		return false;
	}
	conn_log_data(CONN_TRACE, conn, control_frame, conn->len_frame_total,
		      "reading control frame (%u bytes): ", conn->len_frame_total);

	/* Decode the control frame. */
	res = fstrm_control_decode(conn->control,
				   control_frame,
				   conn->len_frame_total,
				   FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success) {
		/* Malformed. */
		return false;
	}

	/* Drain the data read. */
	evbuffer_drain(conn->ev_input, conn->len_frame_total);

	/* Success. */
	return true;
}

static bool
can_read_full_frame(struct conn *conn)
{
	uint32_t tmp[2] = {0};

	/*
	 * This tracks the total number of bytes that must be removed from the
	 * input buffer to read the entire frame. */
	conn->len_frame_total = 0;

	/* Check if the frame length field has fully arrived. */
	if (conn->len_buf < sizeof(uint32_t))
		return false;

	/* Read the frame length field. */
	evbuffer_copyout(conn->ev_input, &tmp[0], sizeof(uint32_t));
	conn->len_frame_payload = ntohl(tmp[0]);

	/* Account for the frame length field. */
	conn->len_frame_total += sizeof(uint32_t);

	/* Account for the length of the frame payload. */
	conn->len_frame_total += conn->len_frame_payload;

	/* Check if this is a control frame. */
	if (conn->len_frame_payload == 0) {
		uint32_t len_control_frame = 0;

		/*
		 * Check if the control frame length field has fully arrived.
		 * Note that the input buffer hasn't been drained, so we also
		 * need to account for the initial frame length field. That is,
		 * there must be at least 8 bytes available in the buffer.
		 */
		if (conn->len_buf < 2*sizeof(uint32_t))
			return false;

		/* Read the control frame length. */
		evbuffer_copyout(conn->ev_input, &tmp[0], 2*sizeof(uint32_t));
		len_control_frame = ntohl(tmp[1]);

		/* Account for the length of the control frame length field. */
		conn->len_frame_total += sizeof(uint32_t);

		/* Enforce minimum and maximum control frame size. */
		if (len_control_frame < sizeof(uint32_t) ||
		    len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX)
		{
			cb_close_conn(conn->bev, 0, conn);
			return false;
		}

		/* Account for the control frame length. */
		conn->len_frame_total += len_control_frame;
	}

	/*
	 * Check if the frame has fully arrived. 'len_buf' must have at least
	 * the number of bytes needed in order to read the full frame, which is
	 * exactly 'len_frame_total'.
	 */
	if (conn->len_buf < conn->len_frame_total) {
		conn_log(CONN_TRACE, conn, "incomplete message (have %zd bytes, want %u)",
			 conn->len_buf, conn->len_frame_total);
		if (conn->len_frame_total > conn->ctx->capture_highwater) {
			conn_log(CONN_WARNING, conn,
				"Skipping %u byte message (%zd buffer)",
				conn->len_frame_total,
				conn->ctx->capture_highwater);
			conn->bytes_skip = conn->len_frame_total;
		}
		return false;
	}

	/* Success. The entire frame can now be read from the buffer. */
	return true;
}

static void
cb_write(struct bufferevent *bev, void *arg)
{
	struct conn *conn = (struct conn *) arg;

	if (conn->state != CONN_STATE_STOPPED)
		return;

	cb_close_conn(bev, 0, arg);
}

static void
cb_read(struct bufferevent *bev, void *arg)
{
	struct conn *conn = (struct conn *) arg;
	conn->bev = bev;
	conn->ev_input = bufferevent_get_input(conn->bev);
	conn->ev_output = bufferevent_get_output(conn->bev);

	for (;;) {
		/* Get the number of bytes available in the buffer. */
		conn->len_buf = evbuffer_get_length(conn->ev_input);

		/* Check if there is any data available in the buffer. */
		if (conn->len_buf <= 0)
			return;

		/* Check if the full frame has arrived. */
		if ((conn->bytes_skip == 0) && !can_read_full_frame(conn))
			return;

		/* Skip bytes of oversized frames. */
		if (conn->bytes_skip > 0) {
			size_t skip = conn->bytes_skip;

			if (skip > conn->len_buf)
				skip = conn->len_buf;

			conn_log(CONN_TRACE, conn, "Skipping %zd bytes", skip);
			evbuffer_drain(conn->ev_input, skip);
			conn->bytes_skip -= skip;
			continue;
		}

		/* Process the frame. */
		if (conn->len_frame_payload > 0) {
			/* This is a data frame. */
			process_data_frame(conn);

		} else {
			/* This is a control frame. */
			if (!load_control_frame(conn)) {
				/* Malformed control frame, shut down the connection. */
				cb_close_conn(conn->bev, 0, conn);
				return;
			}

			if (!process_control_frame(conn)) {
				/*
				 * Invalid control state requested, or the
				 * end-of-stream has been reached. Shut down
				 * the connection.
				 */
				cb_close_conn(conn->bev, 0, conn);
				return;
			}
		}
	}
}

static void
cb_accept_conn(struct evconnlistener *listener, evutil_socket_t fd,
	       __attribute__((unused)) struct sockaddr *sa,
	       __attribute__((unused)) int socklen, void *arg)
{
	struct capture *ctx = (struct capture *) arg;
	struct event_base *base = evconnlistener_get_base(listener);

	/* Set up a bufferevent and per-connection context for the new connection. */
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		if (ctx->args->debug >= CONN_ERROR)
			fprintf(stderr, "%s: bufferevent_socket_new() failed\n",
				argv_program);
		evutil_closesocket(fd);
		return;
	}
	struct conn *conn = conn_init(ctx);
	bufferevent_setcb(bev, cb_read, cb_write, cb_close_conn, (void *) conn);
	bufferevent_setwatermark(bev, EV_READ, 0, ctx->capture_highwater);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	if (ctx->args->debug >= CONN_INFO)
		fprintf(stderr, "%s: accepted new connection fd %d\n", argv_program, fd);

	ctx->remaining_connections--;
	if (ctx->remaining_connections == 0)
		evconnlistener_disable(listener);
}

static void
cb_accept_error(__attribute__((unused)) struct evconnlistener *listener,
	        __attribute__((unused)) void *arg)
{
	const int err = EVUTIL_SOCKET_ERROR();
	fprintf(stderr, "%s: accept() failed: %s\n", argv_program,
		evutil_socket_error_to_string(err));
}

static bool
setup_event_loop(struct capture *ctx)
{
	/* Create the event base. */
	ctx->ev_base = event_base_new();
	if (!ctx->ev_base)
		return false;

	/* Create the evconnlistener. */
	unsigned flags = 0;
	flags |= LEV_OPT_CLOSE_ON_FREE; /* Closes underlying sockets. */
	flags |= LEV_OPT_CLOSE_ON_EXEC; /* Sets FD_CLOEXEC on underlying fd's. */
	flags |= LEV_OPT_REUSEABLE; /* Sets SO_REUSEADDR on listener. */

	ctx->ev_connlistener = evconnlistener_new_bind(ctx->ev_base,
		cb_accept_conn, (void *) ctx, flags, -1,
		(struct sockaddr *) &ctx->ss, ctx->ss_len);
	if (!ctx->ev_connlistener) {
		event_base_free(ctx->ev_base);
		ctx->ev_base = NULL;
		return false;
	}
	evconnlistener_set_error_cb(ctx->ev_connlistener, cb_accept_error);

	/* Success. */
	return true;
}

static void
shutdown_handler(int signum __attribute__((unused)))
{
	event_base_loopexit(g_program_ctx.ev_base, NULL);
}

static bool
setup_signals(void)
{
	struct sigaction sa = {
		.sa_handler = shutdown_handler,
	};

	if (sigemptyset(&sa.sa_mask) != 0)
		return false;
	if (sigaction(SIGTERM, &sa, NULL) != 0)
		return false;
	if (sigaction(SIGINT, &sa, NULL) != 0)
		return false;

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) != 0)
		return false;

	/* Success. */
	return true;
}

static void
cleanup(struct capture *ctx)
{
	argv_cleanup(g_args);

	if (ctx->ev_connlistener != NULL)
		evconnlistener_free(ctx->ev_connlistener);
	if (ctx->ev_base != NULL)
		event_base_free(ctx->ev_base);
}

/*
 * fprintf(stderr, "Quiet text output format mnemonics:\n");
 * fprintf(stderr, "  AQ: AUTH_QUERY\n");
 * fprintf(stderr, "  AR: AUTH_RESPONSE\n");
 * fprintf(stderr, "  RQ: RESOLVER_QUERY\n");
 * fprintf(stderr, "  RR: RESOLVER_RESPONSE\n");
 * fprintf(stderr, "  CQ: CLIENT_QUERY\n");
 * fprintf(stderr, "  CR: CLIENT_RESPONSE\n");
 * fprintf(stderr, "  FQ: FORWARDER_QUERY\n");
 * fprintf(stderr, "  FR: FORWARDER_RESPONSE\n");
 * fprintf(stderr, "  SQ: STUB_QUERY\n");
 * fprintf(stderr, "  SR: STUB_RESPONSE\n");
 * fprintf(stderr, "  TQ: TOOL_QUERY\n");
 * fprintf(stderr, "  TR: TOOL_RESPONSE\n");
 * fprintf(stderr, "\n");
 */

int
main(int argc, char **argv)
{
	/* Parse arguments. */
	if (!parse_args(argc, argv, &g_program_ctx)) {
		usage(NULL);
		return EXIT_FAILURE;
	}
	g_program_ctx.args = &g_program_args;

	if (g_program_ctx.args->str_read_tcp_address != NULL &&
		   g_program_ctx.args->str_read_tcp_port != NULL) {
		if (!open_read_tcp(&g_program_ctx))
			return EXIT_FAILURE;
	} else {
		fprintf(stderr, "%s: failed to setup a listening socket\n", argv_program);
		return EXIT_FAILURE;
	}

	/* Setup the event loop. */
	if (!setup_event_loop(&g_program_ctx)) {
		fprintf(stderr, "%s: failed to setup event loop\n", argv_program);
		return EXIT_FAILURE;
	}

	/* Setup signals. */
	if (!setup_signals()) {
		fprintf(stderr, "%s: failed to setup signals\n", argv_program);
		return EXIT_FAILURE;
	}

	/* Run the event loop. */
	if (event_base_dispatch(g_program_ctx.ev_base) != 0) {
		fprintf(stderr, "%s: failed to start event loop\n", argv_program);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "%s: shutting down\n", argv_program);

	/* Shut down. */
	cleanup(&g_program_ctx);

	/* Success. */
	return EXIT_SUCCESS;
}
