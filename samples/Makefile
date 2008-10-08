MODE = test
CC = gcc
PROGS = vzsock_ssh_cli vzsock_ssh_srv server
OBJ = vzsock_ssh_cli.o vzsock_ssh_srv.o server.o common.o
LIBVZSOCK = ../libvzsock.a
CFLAGS = -g -Wall -O0
INC = -I../
LDFLAGS += -L /usr/kerberos/lib/

LIBD = -Wl,-Bstatic -lcurl -lssl -lcrypto -lz -Wl,-Bdynamic -lpthread -ldl -lresolv -lvzctl
ifeq "${ARCH}" "ia64"
LIBD = -Wl,-Bstatic -lcurl -lssl -lcrypto -lz -Wl,-Bdynamic -lpthread -lresolv -ldl -lvzctl
endif
ifeq "${MODE}" "test"
LIBD = -Wl,-Bstatic -lssl -lcrypto \
	-lgssapi_krb5 -lkrb5 -lkrb5support -lz \
	-lk5crypto -lcom_err \
	-Wl,-Bdynamic -lpthread -ldl -lresolv
# -lkrb5support
endif
all:: ${PROGS}

vzsock_ssh_cli:: vzsock_ssh_cli.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) ${LIBVZSOCK} $(LIBD) -o $@

vzsock_ssh_srv:: vzsock_ssh_srv.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) ${LIBVZSOCK} $(LIBD) -o $@

server:: server.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) ${LIBVZSOCK} $(LIBD) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean::
	rm -f ${PROGS} ${OBJ}

