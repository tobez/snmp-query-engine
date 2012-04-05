CFLAGS=-O3 -g -Wall -Werror

all: snmp-query-engine

snmp-query-engine: main.o event_loop.o
	cc $(CFLAGS) -o snmp-query-engine \
	  main.o event_loop.o

main.o: main.c sqe.h
	cc -c $(CFLAGS) -o main.o main.c

event_loop.o: event_loop.c sqe.h
	cc -c $(CFLAGS) -o event_loop.o event_loop.c

test: test.c
	cc $(CFLAGS) -o test test.c && ./test
