ARCH=$(shell uname -i)

CC = gcc

CFLAGS = -g -Wall -fPIC -O0
# -O2 -D_REENTRANT
LDFLAGS += -L . -L /usr/kerberos/lib/

INC = -I. -I/usr/include -I/usr/kerberos/include

INCLUDEDIR = usr/include/vz
LIBDIR = usr/lib
SAMPLEDIR = usr/share/libvzsock/samples
ifeq "${ARCH}" "x86_64"
LIBDIR = usr/lib64
endif

LIB_MAJOR = 1
LIB_MINOR = 0.1

OBJ = util.o fd.o ssh.o sock.o vzsock.o
ifdef WITH_SSL
OBJ += ssl_util.o ssl.o
LIBS += -lssl
endif

NAME = libvzsock
LIB_FULL = $(NAME).so.$(LIB_MAJOR).$(LIB_MINOR)
LIB_SHORT = $(NAME).so.$(LIB_MAJOR)

default: all
all: $(NAME).a $(NAME).so $(LIB_FULL) $(LIB_SHORT)

$(LIB_FULL): $(OBJ)
	$(CC) $(CFLAGS) $(INC) $(LDFLAGS) -shared --as-needed \
	-Wl,-soname=$(LIB_SHORT) $(LIBS) $^ -o $@

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
	install -d $(DESTDIR)/$(SAMPLEDIR)
	install -m 644 samples/*.{c,h} $(DESTDIR)/$(SAMPLEDIR)/
	install -m 644 samples/Makefile $(DESTDIR)/$(SAMPLEDIR)/

depend:: .depend
.depend:: $(OBJ:.o=.c) $(LOBJ:.lo=.c)
	$(CC) -M $(INC) $^ >.depend

clean:
	rm -rf *.o $(NAME).a $(NAME).so $(LIB_FULL) $(LIB_SHORT)

.PHONY: clean depend install
