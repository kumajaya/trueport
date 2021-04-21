srcdir=.
prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
CC=gcc

SUBDIRS = ptyx

OBJS =  trueportd.o clparse.o pkt_forwarding.o

ifdef SSL
  OBJS +=  ssl_tp.o
  CFLAGS +=  -DUSE_SSL -DOPENSSL_NO_KRB5
  LIBS   += -lssl -lcrypto
endif

CFLAGS += -Wall

# need special config flag for application if on PPC64 or SPARC64
ifeq "$(MACHINE)" "ppc64"
  CFLAGS += -DCONFIG_PPC64
else
	ifeq "$(MACHINE)" "sparc64"
		CFLAGS += -DCONFIG_SPARC64
	endif
endif

# Uncomment line below if you want debug info
#CFLAGS += -g

ifeq "$(CHECK_LIBS)" "yes"
  CHECK_LIBS_FLAGS = -DCHECK_LIBS
  ifndef	SSL
    LIBS   += -lssl -lcrypto
  endif
endif


all: trueportd tpadm swirl $(SUBDIRS)
	@for d in $(SUBDIRS); do 							\
	  echo "-----------------------------------------";	\
	  if ! $(MAKE) -C $$d; then exit 1; fi;			\
	done
	@echo "-----------------------------------------"


trueportd: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o trueportd $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@


testopenssl:	testopenssl.c
	$(CC) $(CFLAGS) $(CHECK_LIBS_FLAGS) $(INCS) testopenssl.c -o testopenssl  $(LIBS)

install:
	rm -f /tmp/files
	@for d in $(SUBDIRS); do if ! $(MAKE) -C $$d install; then exit 1; fi; done
	$(srcdir)/mkinstalldirs $(DESTDIR)$(bindir)
	install -m 755 -s trueportd $(DESTDIR)$(bindir)
	install -m 755 -s tpadm $(DESTDIR)$(bindir)
	install -m 755    addports $(DESTDIR)$(bindir)
	install -m 755    cleanports $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)/etc/trueport
	install -m 755    tplogin $(DESTDIR)/etc/trueport
	install -m 755    addlogins $(DESTDIR)/etc/trueport
	install -m 755    rmlogins $(DESTDIR)/etc/trueport
	install -m 755    swirl $(DESTDIR)/etc/trueport
	touch $(DESTDIR)/etc/trueport/config.tp
	touch $(DESTDIR)/etc/trueport/sslcfg.tp
	touch $(DESTDIR)/etc/trueport/pktfwdcfg.tp
	install -m 755    uninstall.sh $(DESTDIR)/etc/trueport
	install -m 755    postinstall.sh $(DESTDIR)/etc/trueport
	mkdir -p $(DESTDIR)/etc/init.d
	install -m 755 trueport $(DESTDIR)/etc/init.d/trueport
	echo /lib/modules/`uname -r`/misc >> /tmp/files

	mkdir -p $(DESTDIR)/usr/share/doc/trueport/ptyx
	install README $(DESTDIR)/usr/share/doc/trueport/
	install ptyx/* $(DESTDIR)/usr/share/doc/trueport/ptyx
	install tp.h $(DESTDIR)/usr/share/doc/trueport/
	install tp_ver.h $(DESTDIR)/usr/share/doc/trueport/

clean:
	rm -f *.o trueportd tpadm swirl *~
	@for d in $(SUBDIRS); do $(MAKE) -C $$d clean ; done
