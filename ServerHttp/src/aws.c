// SPDX-License-Identifier: BSD-3-Clause

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libaio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "aws.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

// static io_context_t ctx;
static io_context_t ctx;

/* manage possible errors*/
#define ERROR_HANDLER_GENERIC 5000

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *) p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	// get the reply header for god http reply
	const char *reply_header = "HTTP/1.1 200 OK\r\n"
								"Connection: close\r\n"
								"\r\n"; // reply must end with double \r\n
	// get the reply header in the buffer from struct connection
	// initially done with strncpy but it seems to have coding style errors
	memcpy(conn->send_buffer, reply_header, strlen(reply_header)); // set the buffer to be sent
	// get the length of that buffer in the specific field for that from the
	// connection struct
	conn->send_len = strlen(reply_header);
}

static void connection_prepare_send_404(struct connection *conn)
{
	// get the reply in case page was not found ERROR 404
	const char *not_found_header = "HTTP/1.1 404 Not Found\r\n"
									"Connection: close\r\n"
									"\r\n"; // reply must end in double \r\n
	// string shall be placed in the buffer for sending the data
	memcpy(conn->send_buffer, not_found_header, strlen(not_found_header));
	// set the length of the buffer in the connection structure
	conn->send_len = strlen(not_found_header);
}

static enum resource_type
	connection_get_resource_type(struct connection *conn)
{
	// file can be static or dynamic

	// Set the data type to determine whether it will be transmitted synchronously
	// or asynchronously.

	if (strstr(conn->request_path, "static") != NULL)
		return RESOURCE_TYPE_STATIC;

	if (strstr(conn->request_path, "dynamic") != NULL)
		return RESOURCE_TYPE_DYNAMIC;

	return RESOURCE_TYPE_NONE; // bad file
}

struct connection *connection_create(int sockfd)
{
	struct connection *conn = calloc(1, sizeof(*conn));
	// set the socket file descriptor
	conn->sockfd = sockfd;
	// init buffers
	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);
	memset(conn->request_path, 0, BUFSIZ);
	// set event file descriptors to -1 (not assigned)
	conn->fd = -1;
	conn->recv_len = 0;
	conn->send_len = 0;
	conn->file_size = 0;
	conn->eventfd = -1;
	// set have_path flag to 0 (false)
	conn->have_path = 0;
	// the following two will be used as contor for bytes when transferring
	conn->file_pos = 0;
	conn->send_pos = 0;//g
	// initialize asynchronous I/O control block offset to 0
	// note: I used this one more to track the file offset
	conn->iocb.u.c.offset = 0;

	return conn;
}

void connection_remove(struct connection *conn)
{
	dlog(LOG_DEBUG, "\nConnection closed\n");

	close(conn->fd);
	w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	w_epoll_remove_ptr(epollfd, conn->eventfd, conn);

	close(conn->sockfd);
	close(conn->eventfd);
	free(conn);
}

void handle_new_connection(void)
{
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_fd =
		accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
	int flags = fcntl(client_fd, F_GETFL, 0);

	fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
	struct connection *conn;

	conn = connection_create(client_fd);
	conn->state = STATE_INITIAL;

	int rc = w_epoll_add_ptr_in(epollfd, conn->sockfd, conn);

	if (rc)
		dlog(LOG_DEBUG, "Print: %d\n", rc);

	http_parser_init(&(conn->request_parser), HTTP_REQUEST);
	conn->request_parser.data = conn;
}

void receive_data(struct connection *conn)
{
	ssize_t bytes_recv;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);

	if (rc < 0) {
		ERR("get_peer_address");
		conn->state = STATE_CONNECTION_CLOSED;
	}

	bytes_recv = recv(conn->sockfd, conn->recv_buffer + conn->recv_len,
						BUFSIZ - conn->recv_len, 0);
	if (bytes_recv < 0) {
		dlog(LOG_ERR, "Error in communication from: %s\n", abuffer);
		conn->state = STATE_CONNECTION_CLOSED;
	}

	if (bytes_recv == 0) {
		dlog(LOG_INFO, "Connection closed from: %s\n", abuffer);
		conn->state = STATE_CONNECTION_CLOSED;
	}

	// initialize parameters to check is response ends with two newlines
	size_t buffer_length = strlen(conn->recv_buffer);
	const char *last_rn_rn = "\r\n\r\n";
	size_t last_rn_rn_length = strlen(last_rn_rn);

	// user strncmp to compare the calculated length if is the newlines
	if (buffer_length >= last_rn_rn_length &&
		strncmp(conn->recv_buffer + buffer_length - last_rn_rn_length,
				last_rn_rn, last_rn_rn_length) == 0) {
		// when the response contains those, all data was received
		conn->state = STATE_DATA_RECEIVED;
	}
	// if not all data was received, add the byted received the that "offset"
	conn->recv_len += bytes_recv;
}

int connection_open_file(struct connection *conn)
{
	// open file
	conn->fd = open(conn->request_path + 1, O_RDWR);
	// get size of file
	struct stat stat_buf;

	fstat(conn->fd, &stat_buf);
	// set the size found
	conn->file_size = stat_buf.st_size;
	// the intitial file position in file is 0
	conn->file_pos = 0;
	// return the file descriptor of the newly open file
	return conn->fd;
}

int parse_header(struct connection *conn)
{
	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
		.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
		};
	int bytes_parsed =
		http_parser_execute(&(conn->request_parser), &settings_on_path,
								conn->recv_buffer, conn->recv_len);

	if (bytes_parsed < 0)
		dlog(LOG_DEBUG, "Error");

	return 0;
}

enum connection_state connection_send_static(struct connection *conn)
{
	off_t remaining_bytes = conn->file_size - conn->file_pos;

	while (remaining_bytes > 0) {
		ssize_t sent_bytes =
			sendfile(conn->sockfd, conn->fd, NULL, remaining_bytes);

		conn->file_pos += sent_bytes; // this is a contor for the file
		remaining_bytes -= sent_bytes;
	}

	if (conn->file_pos == conn->file_size) {
		// when the position goes from 0 to the total number of bytes, all
		// data was sent
		return STATE_DATA_SENT;
	}

	// in case of fails , data will still be sending
	return STATE_SENDING_DATA;
}

int connection_send_data(struct connection *conn)
{
	int check_heander_404 = 0; // there is no error 404

	dlog(LOG_DEBUG, "%s\n", conn->request_path + 1);

	// when the filepath parsed cannot be accessed => error 404
	if (access((conn->request_path + 1), F_OK) == 0) {
		connection_prepare_send_reply_header(conn);
		conn->send_pos = 0; // start position should be set to 0
	} else {
		connection_prepare_send_404(conn);
		conn->send_pos = 0; // start position should be set to 0
		check_heander_404 = 1; // change to true
	}

	ssize_t bytes_sent;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		ERR("get_peer_address");
		conn->state = STATE_CONNECTION_CLOSED;
	}
	// sendpos is like a counter for the bytes that have been already read
	// send_len is the total number of bytes that need to be sent
	while (conn->send_pos < conn->send_len) {
		bytes_sent = send(conn->sockfd, conn->send_buffer + conn->send_pos,
							conn->send_len - conn->send_pos, 0);
		conn->send_pos += bytes_sent;
	}

	// check which header was sent
	if (conn->send_pos == conn->send_len && check_heander_404 == 0) {
		conn->state = STATE_HEADER_SENT;
		return 0;
	}

	if (conn->send_pos == conn->send_len && check_heander_404 == 1) {
		conn->state = STATE_404_SENT;
		return 0;
	}

	// error checks
	if (bytes_sent < 0) { /* error in communication */
		dlog(LOG_ERR, "Error in communication to %s\n", abuffer);
		conn->state = STATE_CONNECTION_CLOSED;
		return -1;
	}

	if (bytes_sent == 0) { /* connection closed */
		dlog(LOG_INFO, "Connection closed to %s\n", abuffer);
		conn->state = STATE_CONNECTION_CLOSED;
	}

	dlog(LOG_DEBUG, "Sending message to %s\n", abuffer);

	return bytes_sent;
}

/* to init iocb i looked into the libaio.h and used:
 * static inline void io_prep_pread(struct iocb *iocb, int fd, void *buf,
 * size_t count, long long offset). The offset here is the actual offset of
 * the file (where is the file it left). I didnt add a new variable so i used
 * iocb->u.c.offset = offset;
 */
void connection_start_async_io(struct connection *conn)
{
	io_prep_pread(&(conn->iocb), conn->fd, conn->send_buffer, BUFSIZ,
				conn->iocb.u.c.offset);
	conn->piocb[0] = &(conn->iocb);
	// evntfd like syscall - eventfd(0,0);
	io_set_eventfd(&(conn->iocb), conn->eventfd);
	// add eventfd in epoll
	int ret = io_submit(ctx, 1, conn->piocb);

	if (ret)
		dlog(LOG_DEBUG, "mai multe citiri\n");
	conn->send_pos = 0;
}

void connection_complete_async_io(struct connection *conn)
{
	/* Destroy the AIO context */
	io_destroy(ctx);
}

int connection_send_dynamic(struct connection *conn)
{
	struct io_event events[1];
	// iogetevent - creates an instance of the struct io_event based on the number
	// of bytes, similar to fstat
	int ret = io_getevents(ctx, 1, 1, events, NULL);
	// send simple
	while (conn->send_pos < events[0].res) {
		ret = send(conn->sockfd, conn->send_buffer + conn->send_pos,
					events[0].res, 0);

		conn->iocb.u.c.offset += ret;
		conn->send_pos += ret;
	}

	if (ret < 0) { /* error in communication */
		dlog(LOG_ERR, "Error in communication to\n");
		conn->state = STATE_CONNECTION_CLOSED;
		return -1;
	}

	if (ret == 0) { /* connection closed */
		dlog(LOG_INFO, "Connection closed to\n");
		conn->state = STATE_CONNECTION_CLOSED;
	}

	return conn->iocb.u.c.offset;
}

void handle_output(struct connection *conn)
{
	size_t bytes_sent;

	switch (conn->state) {
	case STATE_INITIAL:

	case STATE_RECEIVING_DATA:

	case STATE_REQUEST_RECEIVED:
		parse_header(conn);
		conn->state = STATE_SENDING_DATA;

	case STATE_SENDING_DATA:
		dlog(LOG_DEBUG, "send data\n");
		// handle data sending state
		conn->res_type = connection_get_resource_type(conn);

		if (conn->res_type == RESOURCE_TYPE_STATIC)
			bytes_sent = connection_send_data(conn);

		if (conn->res_type == RESOURCE_TYPE_DYNAMIC)
			bytes_sent = connection_send_data(conn);

		if (conn->res_type == RESOURCE_TYPE_NONE) {
			connection_prepare_send_404(conn);
			while (conn->send_pos < conn->send_len) {
				bytes_sent = send(conn->sockfd,
									conn->send_buffer + conn->send_pos,
								conn->send_len - conn->send_pos, 0);
			conn->send_pos += bytes_sent;
		}
	}

	break;

	case STATE_DATA_SENT:
		// Handle data sent state
		dlog(LOG_DEBUG, "data sent -> connection close\n");
		// conn->state = STATE_CONNECTION_CLOSED;
		conn->state = STATE_CONNECTION_CLOSED;
		break;

	case STATE_HEADER_SENT:
		// Handle header sent state
		dlog(LOG_DEBUG, "header sent -> sending data\n");

		int rc = connection_open_file(conn);

		if (rc)
			dlog(LOG_DEBUG, "rc is okay");

		// conn->res_type = connection_get_resource_type(conn);
		if (conn->res_type == RESOURCE_TYPE_STATIC) {
			conn->state = connection_send_static(conn);
		} else {
			dlog(LOG_DEBUG, "incepe async\n");
			conn->eventfd = eventfd(0, 0);

			int rc = w_epoll_add_ptr_in(epollfd, conn->eventfd, conn);

			if (rc)
				dlog(LOG_DEBUG, "Print: %d\n", rc);
			int ret = io_setup(128, &ctx);

			if (ret)
				dlog(LOG_DEBUG, "Print: %d\n", ret);

redo:
			connection_start_async_io(conn);
			dlog(LOG_DEBUG, "continua async\n");
			bytes_sent = connection_send_dynamic(conn);

			if (bytes_sent < conn->file_size)
				goto redo;

			dlog(LOG_DEBUG, "\nTOTAL BYTES SENT: %d\n", (int)bytes_sent);
			// connection_complete_async_io(conn);
			conn->state = STATE_CONNECTION_CLOSED;
		}
		break;

	case STATE_404_SENT:
		// Handle 404 sent state
		conn->state = STATE_CONNECTION_CLOSED;
		break;
	case STATE_CONNECTION_CLOSED:
		// Handle closed connection state
		conn->state = STATE_CONNECTION_CLOSED;
		connection_remove(conn);
		break;
	default:
		ERR("Unexpected state\n");
		exit(1);
	}
}

void handle_client(uint32_t event, struct connection *conn)
{
	while (!strstr(conn->recv_buffer, "\r\n\r\n"))
		receive_data(conn);

	conn->state = STATE_RECEIVING_DATA;

	int rc = w_epoll_update_ptr_inout(epollfd, conn->sockfd, conn);

	if (rc)
		dlog(LOG_DEBUG, "Print: %d\n", rc);
}

int check_if_connection_closed(struct connection *conn)
{
	if (conn->state == STATE_CONNECTION_CLOSED)
		return 1;
	return 0;
}

int error_handler;

int main(void)
{
	int rc;

	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	dlog(LOG_INFO, "Server waiting for connections on port %d\n",
		AWS_LISTEN_PORT);
	/* server main loop */
	while (1) {
		struct epoll_event rev;

		rc = w_epoll_wait_infinite(epollfd, &rev);

		DIE(rc < 0, "w_epoll_wait_infinite");

		if (rev.data.fd == listenfd) {
			dlog(LOG_DEBUG, "New connection\n");

			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			if (rev.events & EPOLLIN) {
				dlog(LOG_DEBUG, "New message\n");
				handle_client(rev.events, rev.data.ptr);
			}

			if (rev.events & EPOLLOUT) {
				error_handler++;
				if (error_handler == ERROR_HANDLER_GENERIC)
					connection_remove(rev.data.ptr);

				dlog(LOG_DEBUG, "Ready to send message\n");
				handle_output(rev.data.ptr);
			}

			if (check_if_connection_closed(rev.data.ptr) == 1)
				connection_remove(rev.data.ptr);
		}
	}
	return 0;
}
