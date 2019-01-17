NAME_LIBRARY=gnupg.so
ROOT_SOURCES=src
SOURCES=$(ROOT_SOURCES)/module.c $(ROOT_SOURCES)/gnupg.c
ZBX_INCLUDE=../../../include
GPME_INCLUDE=../../../gpgme-1.12.0/include
CFLAGS=-m64 -fPIC -shared -Wall
LDFLAGS=-lgpgme

all:
	gcc $(CFLAGS) $(LDFLAGS) -o $(NAME_LIBRARY) $(SOURCES) -I$(ZBX_INCLUDE) -I$(GPME_INCLUDE)
clean:
	rm -rf *.so