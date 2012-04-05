OPTIMIZE=	-O3 -g
INCPATH=	-I/usr/local/include -I/opt/local/include
LIBPATH=	-L/usr/local/lib -L/opt/local/lib
CFLAGS=	-Wall -Werror $(OPTIMIZE) $(INCPATH)

all: snmp-query-engine

snmp-query-engine: main.o event_loop.o carp.o
	cc $(CFLAGS) -o snmp-query-engine \
	  main.o event_loop.o carp.o \
	  $(LIBPATH) -lJudy -lmsgpack

main.o: main.c sqe.h
	cc -c $(CFLAGS) -o main.o main.c

event_loop.o: event_loop.c sqe.h
	cc -c $(CFLAGS) -o event_loop.o event_loop.c

carp.o: carp.c sqe.h
	cc -c $(CFLAGS) -o carp.o carp.c

test: test.c
	cc $(CFLAGS) -o test test.c && ./test
