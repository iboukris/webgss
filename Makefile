# MIT Licensed, see LICENSE file
# Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

CC = emcc
AR = emar

CPPFLAGS = -Ikrb5/src/include
CFLAGS = -Os
LIBS = -l_emwrap
LDFLAGS = -L$(realpath .)
WGLDFLAGS = -L$(realpath krb5/src/lib)

# -s SYSCALL_DEBUG=1
DEBUG_OPTIONS =
SANIT_OPTIONS =

K5_CONF = -disable-pkinit --disable-rpath --disable-thread-support --disable-shared --enable-static --with-tls-impl=no --without-keyutils
K5_LIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lapputils -lkrb5support

# -s STRICT=1 -s EXPORTED_FUNCTIONS=_getenv,_setenv -s EXPORTED_RUNTIME_METHODS=ccall,cwrap
EM_ARGS = -s MODULARIZE=1
EMBEDK5 = --embed-file embed_k5.conf@/etc/krb5.conf


.PHONY: all clean test check debug

all: lib/k5lib.js lib/k5lib_node.js

debug: DEBUG_OPTIONS = -s SOCKET_DEBUG=1 -s FS_DEBUG=1 -s ASSERTIONS=2 -s ALLOW_MEMORY_GROWTH=1
debug: SANIT_OPTIONS = -fsanitize=address
debug: CFLAGS = -g -O0 -Wall
debug: lib/k5lib_node.js lib/k5lib.js


lib_emwrap.a:
	$(CC) -c emwrap.c -o emwrap.o
	$(AR) rcs lib_emwrap.a emwrap.o

krb5/src/configure:
	cd krb5/src && git reset --hard HEAD && git apply ../../upstream.patch
	cd krb5/src && autoreconf -if
	cd krb5/src && CFLAGS="$(CFLAGS)" LIBS=$(LIBS) LDFLAGS=$(LDFLAGS) emconfigure ./configure $(K5_CONF)

krb5/src/lib/libkrb5.a: lib_emwrap.a krb5/src/configure
	cd krb5/src && emmake $(MAKE) $(DEBUG_OPTIONS)

utils.o: krb5/src/lib/libkrb5.a utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c utils.c -o utils.o $(SANIT_OPTIONS)

k5drv.o: krb5/src/lib/libkrb5.a k5drv.cpp
	$(CC) $(CPPFLAGS) $(CFLAGS) -c k5drv.cpp -o k5drv.o $(SANIT_OPTIONS)

k5lib.o: krb5/src/lib/libkrb5.a k5lib.cpp
	$(CC) $(CPPFLAGS) $(CFLAGS) -c k5lib.cpp -o k5lib.o $(SANIT_OPTIONS)

lib/k5lib.js: krb5/src/lib/libkrb5.a utils.o k5drv.o k5lib.o
	mkdir -p lib
	$(CC) $(CFLAGS) --bind utils.o k5drv.o k5lib.o $(K5_LIBS) $(LIBS) $(LDFLAGS) $(WGLDFLAGS) -o lib/k5lib.js -s EXPORT_ES6=1 -s EXPORT_NAME=createEmModule -s ENVIRONMENT=web $(EM_ARGS) $(SANIT_OPTIONS) $(DEBUG_OPTIONS) $(EMBEDK5)

# node isn't happy with EXPORT_ES6 so let it have its own build for now
lib/k5lib_node.js: krb5/src/lib/libkrb5.a utils.o k5drv.o k5lib.o
	mkdir -p lib
	$(CC) $(CFLAGS) --bind utils.o k5drv.o k5lib.o $(K5_LIBS) $(LIBS) $(LDFLAGS) $(WGLDFLAGS) -o lib/k5lib_node.js -s ENVIRONMENT=node $(EM_ARGS) $(SANIT_OPTIONS) $(DEBUG_OPTIONS) $(EMBEDK5)


test: check

check: all
	./run_tests.sh


clean:
	rm -rf utils.o k5drv.o k5lib.o lib testdir_wgss
	cd krb5/src && emmake $(MAKE) clean
	rm -f emwrap.o lib_emwrap.a
