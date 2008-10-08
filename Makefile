ARCH=$(shell uname -i)

CC = gcc

CFLAGS = -g -Wall -fPIC -O0
# -O2 -D_REENTRANT
LDFLAGS += -L . -L /usr/kerberos/lib/

INC = -I. -I/usr/include

INCLUDEDIR = usr/include/vz
LIBDIR = usr/lib
ifeq "${ARCH}" "x86_64"
LIBDIR = usr/lib64
endif

LIB_MAJOR = 1
LIB_MINOR = 0.1

OBJ = util.o fd.o ssh.o sock.o ssl.o vzsock.o

NAME = libvzsock
LIB_FULL = $(NAME).so.$(LIB_MAJOR).$(LIB_MINOR)
LIB_SHORT = $(NAME).so.$(LIB_MAJOR)

default: all
all: $(NAME).a $(NAME).so $(LIB_FULL) $(LIB_SHORT)

$(LIB_FULL): $(OBJ)
	$(CC) $(CFLAGS) $(INC) $(LDFLAGS) -shared --as-needed \
	-Wl,-soname=$(LIB_SHORT) -lssl $^ -o $@

$(NAME).so: $(LIB_FULL)
	ln -sf $(LIB_FULL) $(NAME).so
	ln -sf $(LIB_FULL) $(LIB_SHORT)

$(NAME).a: $(OBJ)
	ar scq $@ $+
	ranlib $@

.c.o:
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

install:
	install -d $(DESTDIR)/$(INCLUDEDIR)
	install -d $(DESTDIR)/$(LIBDIR)
	install -s -m 644 $(LIB_FULL) $(DESTDIR)/$(LIBDIR)/
	cp -af $(LIB_SHORT) $(DESTDIR)/$(LIBDIR)/
	install -m 644 $(NAME).h $(DESTDIR)/$(INCLUDEDIR)/
	install -m 644 $(NAME).a $(DESTDIR)/$(LIBDIR)/
	cp -af $(NAME).so $(DESTDIR)/$(LIBDIR)/

depend:: .depend
.depend:: $(OBJ:.o=.c) $(LOBJ:.lo=.c)
	$(CC) -M $(INC) $^ >.depend

clean:
	rm -rf *.o $(NAME).a $(NAME).so $(LIB_FULL) $(LIB_SHORT)

.PHONY: clean depend install
