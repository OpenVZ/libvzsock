MODE = test
CC = gcc
PROGS = client vzsock_ssh_srv server
OBJ = client.o vzsock_ssh_srv.o server.o common.o
CFLAGS = -g -Wall -O0
INC = -I../
ARCH=$(shell uname -m)
ifeq "${ARCH}" "x86_64"
LDFLAGS += -L /usr/kerberos/lib64/
else
LDFLAGS += -L /usr/kerberos/lib/
endif

LIBD = -Wl,-Bstatic -lvzsock -lcurl -lssl -lcrypto -lz -Wl,-Bdynamic -lpthread -ldl -lresolv -lvzctl
ifeq "${ARCH}" "ia64"
LIBD = -Wl,-Bstatic -lvzsock -lcurl -lssl -lcrypto -lz -Wl,-Bdynamic -lpthread -lresolv -ldl -lvzctl
endif
ifeq "${MODE}" "test"
LIBD = -Wl,-Bstatic -lvzsock -lssl -lcrypto \
	-lkrb5 -lz \
	-lk5crypto -lcom_err \
	-Wl,-Bdynamic -lpthread -ldl -lresolv
# -lgssapi_krb5 -lkrb5support
# -lkrb5support
endif
all:: ${PROGS}

client:: client.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBD) -o $@

vzsock_ssh_srv:: vzsock_ssh_srv.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBD) -o $@

server:: server.o common.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBD) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean::
	rm -f ${PROGS} ${OBJ}

