CC       = gcc

LIB      = lib

CFLAGS  += -I $(LIB) -Wall -ansi -pedantic -std=gnu11 -O3 -DDEBUG -g
CFLAGS  += -I $(LIB) -Wall -ansi -pedantic -std=gnu11 -O3 -g
LDFLAGS += -pthread -lpcap -lrt

OFILES  = rijndael.o panon.o crypto.o parser.o anon.o

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o : %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

OEXE = anon

all: $(OFILES)
	$(CC) -o $(OEXE) $(OFILES) $(LDFLAGS)

distclean:
	/bin/rm -f *.o $(OEXE)

clean:
	/bin/rm -f *.o *~
