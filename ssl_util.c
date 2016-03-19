/* $Id: ssl.c 130669 2008-07-04 11:19:36Z krasnov $
 *
 * Copyright (c) 2016 Parallels IP Holdings GmbH
 *
 * This file is part of OpenVZ libraries. OpenVZ is free software; you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/> or write to Free Software Foundation,
 * 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
 *
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <syslog.h>

#include "ssl.h"
#include "util.h"

#define BUFFSIZE 16384

/* recursive dump of the error stack */
static void ssl_error_stack(struct vzsock_ctx *ctx)
{
	unsigned long err;
	char buffer[SSL_ERR_STRING_MAXLEN];

	err = ERR_get_error();
	if (err == 0)
		return;
	ssl_error_stack(ctx);
	ERR_error_string_n(err, buffer, sizeof(buffer));
	_vz_logger(ctx, LOG_ERR, "SSL error stack: %lu : %s", err, buffer);
}

int ssl_error(struct vzsock_ctx *ctx, int rc, const char *title)
{
	char buffer[SSL_ERR_STRING_MAXLEN];
	ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
	ssl_error_stack(ctx);
	return _vz_error(ctx, rc, "%s: %s", title, buffer);
}

int ssl_select(
		struct vzsock_ctx *ctx, 
		int sock, 
		int err, 
		int silent)
{
	int rc;
	fd_set fds;
	struct timeval tv;

	do {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = ctx->tmo;
		tv.tv_usec = 0;
		/* for SSL_ERROR_WANT_CONNECT and SSL_ERROR_WANT_ACCEPT
		   "select() or poll() for writing on the socket file 
		   descriptor can be used." - SSL_get_error man page */
		if (err == SSL_ERROR_WANT_READ)
			rc = select(sock + 1, &fds, NULL, NULL, &tv);
		else
			rc = select(sock + 1, NULL, &fds, NULL, &tv);
		if (rc == 0) {
			if (silent)
				_vz_def_logger(LOG_ERR, 
					"timeout (%ld sec)", ctx->tmo);
			else
				_vz_logger(ctx, LOG_ERR, 
					"timeout (%d sec)", ctx->tmo);
			return VZS_ERR_TIMEOUT;
		} else if (rc <= 0) {
			if (silent)
				_vz_def_logger(LOG_ERR, "select() : %m");
			else
				_vz_logger(ctx, LOG_ERR, "select() : %m");
			return VZS_ERR_CONN_BROKEN;
		}
	} while (!FD_ISSET(sock, &fds));

	return 0;
}

int ssl_shutdown(struct vzsock_ctx *ctx, SSL *ssl, int sock)
{
	int rc = 0;
	int sslrc, err;

	while (1) {
		if ((sslrc = SSL_shutdown(ssl)) > 0)
			break;
		err = SSL_get_error(ssl, sslrc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (sslrc == 0)
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_shutdown() : unexpected EOF"); 
			else if (errno == EINTR)
				continue;
			else
				rc = _vz_error(ctx, VZS_ERR_CONN_BROKEN,
					"SSL_shutdown() : %m");
			break;
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ))
		{
			rc = ssl_error(ctx, VZS_ERR_SSL, "SSL_shutdown()");
			break;
		}
		if ((rc = ssl_select(ctx, sock, err, 0)))
			break;
	}

	return rc;
}

/* Write <size> bytes of <data> in non-blocking <ssl> connection.
   In <silent> mode we can't use _vz_error()/_vz_logger() in this function 
   because on server side _vz_error() can call this function to send error 
   message to client side. */
int ssl_write(
		struct vzsock_ctx *ctx, 
		void *conn, 
		const char * data, 
		size_t size,
		int silent)
{
	int rc = 0;
	size_t sent = 0;
	int err;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (size == 0)
		return 0;

	while (1) {
		rc = SSL_write(cn->ssl, data + sent, 
			(unsigned int)(size - sent));
		if (rc > 0) {
			sent += rc;
			if (sent >= size)
				return 0;
			continue;
		}
		err = SSL_get_error(cn->ssl, rc);
		if (err == SSL_ERROR_SYSCALL)
		{
			if (rc == 0) {
				if (silent)
					_vz_def_logger(LOG_ERR,
						"SSL_write() : unexpected EOF");
				else
					_vz_logger(ctx, LOG_ERR, 
						"SSL_write() : unexpected EOF");
				return VZS_ERR_CONN_BROKEN; 
			} else if (errno == EINTR) {
				continue;
			} else {
				if (silent)
					_vz_def_logger(LOG_ERR, 
						"SSL_write() : %m");
				else
					_vz_logger(ctx, LOG_ERR, 
						"SSL_write() : %m");
				return VZS_ERR_CONN_BROKEN; 
			}
		}
		else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ)) 
		{
			if (silent)
				_vz_def_logger(LOG_ERR, "SSL_write() error");
			else
				ssl_error(ctx, VZS_ERR_CONN_BROKEN, 
					"SSL_write()");
			return VZS_ERR_CONN_BROKEN; 
		}
		if ((rc = ssl_select(ctx, cn->sock, err, silent)))
			break;
	}

	return rc;
}

/* redirect stdout to ssl, ssl to stdin */
int ssl_redirect(
		struct vzsock_ctx *ctx, 
		SSL *ssl, 
		int in, 
		int out, 
		int err) 
{
	int rc;
	struct timeval tv;
	char buffer[BUFSIZ + 1];
	int sock; 
	fd_set rd_set, wr_set;
	int fdmax;
	int num, errcode;
	char *str, *token;

	char pipe_buff[BUFFSIZE]; /* Pipe read buffer */
	char ssl_buff[BUFFSIZE]; /* SSL read buffer */
	int pipe_ptr, ssl_ptr; /* Index of first unused byte in buffer */
	int pipe_bytes, ssl_bytes; /* Bytes written to pipe and ssl */
	int pipe_rd, pipe_wr, ssl_rd, ssl_wr;
	int check_SSL_pending;

	sock = SSL_get_fd(ssl);

	_vz_set_nonblock(out);
	_vz_set_nonblock(err);
	_vz_set_nonblock(sock);
	_vz_set_nonblock(in);
	fdmax = (out > err) ? out : err;
	fdmax = (fdmax > sock) ? fdmax : sock;
	fdmax = (fdmax > in) ? fdmax : in;

	pipe_ptr = ssl_ptr = 0;
	pipe_rd = pipe_wr = ssl_rd = ssl_wr = 1;
	pipe_bytes = ssl_bytes = 0;

	while (((pipe_rd || pipe_ptr) && ssl_wr) || ((ssl_rd || ssl_ptr) && pipe_wr)) {

		FD_ZERO(&rd_set); /* Setup rd_set */
		if (pipe_rd && (pipe_ptr < BUFFSIZE)) /* pipe input buffer not full*/
			FD_SET(out, &rd_set);
		if (ssl_rd && ((ssl_ptr < BUFFSIZE) || /* SSL input buffer not full */
			(pipe_ptr && SSL_want_read(ssl))
			/* I want to SSL_write but read from the underlying */
			/* socket needed for the SSL protocol */
			)) {
			FD_SET(sock, &rd_set);
		}
		if (err != -1)
			FD_SET(err, &rd_set);

		FD_ZERO(&wr_set); /* Setup wr_set */
		if (pipe_wr && ssl_ptr) /* SSL input buffer not empty */
			FD_SET(in, &wr_set);
		if (ssl_wr && (pipe_ptr || /* pipe input buffer not empty */
			((ssl_ptr < BUFFSIZE) && SSL_want_write(ssl))
			/* I want to SSL_read but write to the underlying */
			/* socket needed for the SSL protocol */
			)) {
			FD_SET(sock, &wr_set);
		}

		tv.tv_sec = ctx->tmo;
		tv.tv_usec = 0;
		while ((rc = select(fdmax + 1, &rd_set, &wr_set, NULL, &tv)) == -1)
			if (errno != EINTR)
				break;
		if (rc == 0) {
			return _vz_error(ctx, VZS_ERR_TIMEOUT,
				"timeout exceeded (%d sec)", ctx->tmo);
		} else if (rc <= 0) {
			return _vz_error(ctx, VZS_ERR_CONN_BROKEN, "select() : %m");
		}

		/* Set flag to try and read any buffered SSL data if we made */
		/* room in the buffer by writing to the pipe */
		check_SSL_pending = 0;

		if (pipe_wr && FD_ISSET(in, &wr_set)) {
			switch(num = write(in, ssl_buff, ssl_ptr)) {
			case -1: /* error */
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
						"write() : %m");
				}
				break;
			case 0:
				/* No data written to the socket: retrying */
				break;
			default:
				memmove(ssl_buff, ssl_buff+num, ssl_ptr-num);
				if(ssl_ptr==BUFFSIZE)
					check_SSL_pending=1;
				ssl_ptr -= num;
				pipe_bytes += num;
				if ((ssl_rd == 0) && (ssl_ptr == 0)) {
					close(in);
					_vz_logger(ctx, LOG_DEBUG,
						"Pipe write shutdown "
						"(no more data to send)");
					pipe_wr = 0;
				}
			}
		}

		if (ssl_wr && ( /* SSL sockets are still open */
			(pipe_ptr && FD_ISSET(sock, &wr_set)) ||
			/* See if application data can be written */
			(SSL_want_read(ssl) && FD_ISSET(sock, &rd_set))
			/* I want to SSL_write but read from the underlying */
			/* socket needed for the SSL protocol */
			)) {
			num = SSL_write(ssl, pipe_buff, pipe_ptr);

			errcode = SSL_get_error(ssl, num);
			switch(errcode) {
			case SSL_ERROR_NONE:
				memmove(pipe_buff, pipe_buff+num, pipe_ptr-num);
				pipe_ptr -= num;
				ssl_bytes += num;
				/* if pipe reading already closed and pipe 
				   buffer is empty, close ssl writing */
				if ((pipe_rd == 0) && (pipe_ptr == 0) && ssl_wr){
					SSL_shutdown(ssl); /* Send close_notify */
					_vz_logger(ctx, LOG_DEBUG,
						"SSL write shutdown "
						"(no more data to send)");
					ssl_wr = 0;
				}
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				break;
			case SSL_ERROR_SYSCALL:
				if (num < 0) { /* really an error */
					if (errno == EINTR)
						break;
					return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
						"SSL_write() : %m");
				}
				break;
			case SSL_ERROR_ZERO_RETURN: /* close_notify received */
				_vz_logger(ctx, LOG_DEBUG, 
					"connection closed on SSL_write()");
				ssl_rd = ssl_wr = 0;
				break;
			case SSL_ERROR_SSL:
			default:
				return ssl_error(ctx, VZS_ERR_SSL, "SSL_write()");
			}
		}

		if (pipe_rd && FD_ISSET(out, &rd_set)) {
			num = read(out, pipe_buff+pipe_ptr, 
				sizeof(pipe_buff)-pipe_ptr);
			switch (num) {
			case -1:
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
						"read() : %m");
				}
				break;
			case 0: /* close */
				_vz_logger(ctx, LOG_DEBUG, "Pipe closed on read");
				pipe_rd = 0;
				/* if pipe buffer is empty, close ssl writing */
				if ((pipe_ptr == 0) && ssl_wr) {
					SSL_shutdown(ssl); /* Send close_notify */
					_vz_logger(ctx, LOG_DEBUG,
						"SSL write shutdown "
						"(output buffer empty)");
					ssl_wr = 0;
				}
				break;
			default:
				pipe_ptr += num;
			}
		}

		if (ssl_rd && ( /* SSL sockets are still open */
			((ssl_ptr < BUFFSIZE) && FD_ISSET(sock, &rd_set)) ||
			/* See if there's any application data coming in */
			(SSL_want_write(ssl) && FD_ISSET(sock, &wr_set)) ||
			/* I want to SSL_read but write to the underlying */
			/* socket needed for the SSL protocol */
			(check_SSL_pending && SSL_pending(ssl))
			/* Write made space from full buffer */
			)) {
			num = SSL_read(ssl, ssl_buff+ssl_ptr, 
				sizeof(ssl_buff)-ssl_ptr);

			errcode = SSL_get_error(ssl, num);
			switch(errcode) {
			case SSL_ERROR_NONE:
				ssl_ptr += num;
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				break;
			case SSL_ERROR_SYSCALL:
				if (num < 0) { /* not EOF */
					if (errno == EINTR)
						break;
					return _vz_error(ctx, VZS_ERR_CONN_BROKEN,
						"SSL_read() : %m");
				}
				_vz_logger(ctx, LOG_DEBUG, "SSL_read() : EOF");
				ssl_rd = ssl_wr = 0;
				break;
			case SSL_ERROR_ZERO_RETURN: /* close_notify received */
				_vz_logger(ctx, LOG_DEBUG, 
					"connection closed on SSL_read()");
				ssl_rd = 0;
				if ((pipe_ptr == 0) && ssl_wr) {
					SSL_shutdown(ssl); /* Send close_notify back */
					_vz_logger(ctx, LOG_DEBUG,
						"SSL write shutdown "
						"(output buffer empty)");
					ssl_wr = 0;
				}
				if((ssl_ptr == 0) && pipe_wr) {
					close(in);
					_vz_logger(ctx, LOG_DEBUG,
						"Pipe write shutdown "
						"(output buffer empty)");
					pipe_wr = 0;
				}
				break;
			case SSL_ERROR_SSL:
			default:
				return ssl_error(ctx, VZS_ERR_SSL, "SSL_read()");
			}
		}

		if (FD_ISSET(err, &rd_set)) {
			/* logger */
			num = read(err, buffer, sizeof(buffer));
			switch (num) {
			case -1:
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					_vz_logger(ctx, LOG_ERR, 
						"read(stderr) : %m");
				}
				break;
			case 0:
				break;
			default:
				buffer[num] = '\0';
				for (str = buffer; ;str = NULL) {
					if ((token = strtok(str, "\n")) == NULL)
						break;
					if (strlen(token) == 0)
						continue;
					_vz_logger(ctx, LOG_ERR, token);
				}
				break;
			}
		}
	}
	_vz_logger(ctx, LOG_DEBUG, "pipe_bytes = %d, ssl_bytes = %d", 
		pipe_bytes, ssl_bytes);
	return 0;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	int err;

	if (preverify_ok)
		return 1;

	err = X509_STORE_CTX_get_error(ctx);
	syslog(LOG_ERR, "verify error:num=%d:%s\n", err, X509_verify_cert_error_string(err));
	fprintf(stderr, "verify error:num=%d:%s\n", err, X509_verify_cert_error_string(err));
	/* will ignore X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT error */
	if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
		return 1;

	return 0;
}

