# AOS runs `make` and `make install DESTDIR=""` with $out set to the
# package's output directory.
CFLAGS ?= -O2

hello: hello.c
	$(CC) $(CFLAGS) -o $@ hello.c

install: hello
	mkdir -p $(out)/bin
	cp hello $(out)/bin/hello

.PHONY: install
