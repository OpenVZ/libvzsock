CC = gcc
PROGS = vzsock_ssh_cli vzsock_ssh_srv
OBJ = vzsock_ssh_cli.o vzsock_ssh_srv.o
LIBVZSOCK = ../libvzsock.a
CFLAGS = -g -Wall -O0
INC = -I../

all:: ${PROGS}

vzsock_ssh_cli:: vzsock_ssh_cli.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) ${LIBVZSOCK}

vzsock_ssh_srv:: vzsock_ssh_srv.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) ${LIBVZSOCK}

.c.o:
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean::
	rm -f ${PROGS} ${OBJ}

