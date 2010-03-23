#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <libgen.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libvzsock.h>

#include "sample.h"

char progname[NAME_MAX];
int debug = 0;
int transport = VZSOCK_SOCK;

static void usage()
{
	fprintf(stderr, 
"Virtuozzo vzsock test client\n" \
"Usage:\n" \
"%s [-v] [-t <option>]\n" \
"%s -h\n" \
"  Options:\n" \
"    -t/--transport socket|ssh|ssl   select transport (default value is socket)\n" \
"    -v/--verbose                    be verbose\n" \
"    -h/--help                       show usage and exit\n",
	progname, progname);
}

static int parse_cmd_line(int argc, char *argv[])
{
	int c;
	struct option options[] =
	{
		{"transport", required_argument, NULL, 'v'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "vht:", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case 'v':
			debug = 1;
			break;
		case 't':
			if (optarg == NULL) {
				usage();
				exit(EXIT_FAILURE);
			}
			if (strcasecmp(optarg, "ssh") == 0) {
				transport = VZSOCK_SSH;
			} else if (strcasecmp(optarg, "ssl") == 0) {
				transport = VZSOCK_SSL;
			} else if (strcasecmp(optarg, "sock") == 0) {
				transport = VZSOCK_SOCK;
			} else {
				usage();
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
	return 0;
}

static int logger(int level, const char* fmt, va_list pvar)
{
	va_list ap;
	FILE *fp = (level <= LOG_WARNING) ? stderr : stdout;
	/* put to syslog and to some output also */
	va_copy(ap, pvar);
	vsyslog(level, fmt, ap);
	va_end(ap);
	vfprintf(fp, fmt, pvar);
	fputc('\n', fp);
	return 0;
}

/*
void terminate(int signum)
{
	// send sigterm to all processes in group
	kill(0, SIGTERM);

	unlink(pidfile);
	exit(-MIG_ERR_TERM);
}
*/

int main(int argc, char *argv[])
{
	int rc;
	struct vzsock_ctx ctx;
	void *conn;
	int debug = LOG_DEBUG;
	char buffer[BUFSIZ];
	size_t bufsize; 
	char lname[PATH_MAX];
	char lpath[PATH_MAX];
	char rpath[PATH_MAX];
	char hostname[BUFSIZ];
	char *p;
	struct sigaction sigact;
	char * const targs[] = { 
			"tar", 
			"-c", 
			"-S", 
			"--ignore-failed-read", 
			"--numeric-owner", 
			"-f", 
			"-", 
			"-C", 
			lpath, 
			lname,
			NULL };

	if (argc != 3) {
		fprintf(stderr, "Usage : %s localpath remotepath\n", argv[0]);
		return 1;
	}
	parse_cmd_line(argc, argv);

	/* parse local path */
	strncpy(buffer, argv[optind], sizeof(buffer));
	strncpy(lname, basename(buffer), sizeof(lname));
	strncpy(lpath, dirname(buffer), sizeof(lpath));
	/* parse remote path */
	strncpy(buffer, argv[optind+1], sizeof(buffer));
	if (*buffer == '/') {
		strncpy(hostname, "localhost", sizeof(hostname));
		strncpy(rpath, buffer, sizeof(rpath));
	} else {
		if ((p = strrchr(buffer, ':'))) {
			*p = '\0';
			strncpy(rpath, p+1, sizeof(rpath));
		} else {
			strncpy(rpath, "/tmp/", sizeof(rpath));
		}
		strncpy(hostname, buffer, sizeof(hostname));
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
//	sigact.sa_handler = terminate;
//	sigaction(SIGTERM, &sigact, NULL);
	sigact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sigact, NULL);

	if ((rc = vzsock_init(transport, &ctx))) {
		fprintf(stderr, "vzsock_init() return %d\n", rc);
		return -1;
	}
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)logger, sizeof(&logger));

	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_HOSTNAME, (void *)hostname, strlen(hostname)+1))) {
		fprintf(stderr, "vzsock_set() return %d\n", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_set(&ctx, VZSOCK_DATA_SERVICE, (void *)VZSOCK_TEST_PORT, strlen(VZSOCK_TEST_PORT)+1))) {
		fprintf(stderr, "vzsock_set() return %d\n", rc);
		goto cleanup_0;
	}

	if ((rc = vzsock_open(&ctx))) {
		fprintf(stderr, "vzsock_open() return %d\n", rc);
		goto cleanup_0;
	}
	if (transport == VZSOCK_SSH) {
		char * const args[] = {"vzsock_ssh_srv", NULL};
		rc = vzsock_open_conn(&ctx, (void *)args, &conn);
	} else {
		rc = vzsock_open_conn(&ctx, NULL, &conn);
	}
	if (rc) {
		fprintf(stderr, "vzsock_create_conn() return %d\n", rc);
		goto cleanup_0;
	}

	/* send first command and wait reply */
	if ((rc = vzsock_send(&ctx, conn, CMD_INIT, strlen(CMD_INIT)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	bufsize = sizeof(buffer);
	if ((rc = vzsock_recv_str(&ctx, conn, buffer, &bufsize))) {
		fprintf(stderr, "vzsock_recv_str() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);

	/* copy dir */
	snprintf(buffer, sizeof(buffer), CMD_COPY " %s", rpath);
	if ((rc = vzsock_send(&ctx, conn, buffer, strlen(buffer)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	bufsize = sizeof(buffer);
	if ((rc = vzsock_recv_str(&ctx, conn, buffer, &bufsize))) {
		fprintf(stderr, "vzsock_recv_str() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);
	if ((rc = vzsock_send_data(&ctx, conn, targs))) {
		fprintf(stderr, "vzsock_send_data() return %d\n", rc);
		goto cleanup_1;
	}

	/* close connection */
	if ((rc = vzsock_send(&ctx, conn, CMD_CLOSE, strlen(CMD_CLOSE)+1))) {
		fprintf(stderr, "vzsock_send() return %d\n", rc);
		goto cleanup_1;
	}
	bufsize = sizeof(buffer);
	if ((rc = vzsock_recv_str(&ctx, conn, buffer, &bufsize))) {
		fprintf(stderr, "vzsock_recv_str() return %d\n", rc);
		goto cleanup_1;
	}
	fprintf(stdout, "reply is %s\n", buffer);
cleanup_1:
	vzsock_close_conn(&ctx, conn);
cleanup_0:
	vzsock_close(&ctx);

	return rc;
}
