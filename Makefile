CC?=	cc
OPTIMIZE=	-O3 -g
INCPATH=	-I/usr/local/include -I/opt/local/include
LIBPATH=	-L/usr/local/lib -L/opt/local/lib
CFLAGS=	-Wall -Werror $(OPTIMIZE) $(INCPATH)

all: snmp-query-engine test_ber test_msgpack

STDOBJ=event_loop.o carp.o client_input.o client_listen.o opts.o util.o destination.o \
	client_requests_info.o cid_info.o ber.o oid_info.o sid_info.o \
	snmp.o
STDLINK=$(STDOBJ) $(LIBPATH) -lJudy -lmsgpack

clean:
	rm -f *.o snmp-query-engine test_ber test_msgpack *.core core

snmp-query-engine: main.o $(STDOBJ)
	$(CC) $(CFLAGS) -o snmp-query-engine main.o $(STDLINK)

main.o: main.c sqe.h
	$(CC) -c $(CFLAGS) -o main.o main.c

event_loop.o: event_loop.c sqe.h
	$(CC) -c $(CFLAGS) -o event_loop.o event_loop.c

carp.o: carp.c sqe.h
	$(CC) -c $(CFLAGS) -o carp.o carp.c

opts.o: opts.c sqe.h
	$(CC) -c $(CFLAGS) -o opts.o opts.c

util.o: util.c sqe.h
	$(CC) -c $(CFLAGS) -o util.o util.c

client_input.o: client_input.c sqe.h
	$(CC) -c $(CFLAGS) -o client_input.o client_input.c

client_listen.o: client_listen.c sqe.h
	$(CC) -c $(CFLAGS) -o client_listen.o client_listen.c

destination.o: destination.c sqe.h
	$(CC) -c $(CFLAGS) -o destination.o destination.c

client_requests_info.o: client_requests_info.c sqe.h
	$(CC) -c $(CFLAGS) -o client_requests_info.o client_requests_info.c

cid_info.o: cid_info.c sqe.h
	$(CC) -c $(CFLAGS) -o cid_info.o cid_info.c

sid_info.o: sid_info.c sqe.h
	$(CC) -c $(CFLAGS) -o sid_info.o sid_info.c

ber.o: ber.c sqe.h
	$(CC) -c $(CFLAGS) -o ber.o ber.c

snmp.o: snmp.c sqe.h
	$(CC) -c $(CFLAGS) -o snmp.o snmp.c

oid_info.o: oid_info.c sqe.h
	$(CC) -c $(CFLAGS) -o oid_info.o oid_info.c

test_ber: test_ber.c $(STDOBJ)
	$(CC) $(CFLAGS) -o test_ber test_ber.c $(STDLINK)

test_msgpack: test_msgpack.c $(STDOBJ)
	$(CC) $(CFLAGS) -o test_msgpack test_msgpack.c $(STDLINK)

test: snmp-query-engine
	prove t/queries.t

test-details: snmp-query-engine
	perl t/queries.t
