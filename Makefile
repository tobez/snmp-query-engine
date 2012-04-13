OPTIMIZE=	-O3 -g
INCPATH=	-I/usr/local/include -I/opt/local/include
LIBPATH=	-L/usr/local/lib -L/opt/local/lib
CFLAGS=	-Wall -Werror $(OPTIMIZE) $(INCPATH)

all: snmp-query-engine test_ber test_msgpack

STDOBJ=event_loop.o carp.o client_input.o client_listen.o opts.o util.o destination.o \
	client_requests_info.o
STDLINK=$(STDOBJ) $(LIBPATH) -lJudy -lmsgpack

clean:
	rm -f *.o snmp-query-engine test_ber test_msgpack *.core core

snmp-query-engine: main.o $(STDOBJ)
	cc $(CFLAGS) -o snmp-query-engine main.o $(STDLINK)

main.o: main.c sqe.h
	cc -c $(CFLAGS) -o main.o main.c

event_loop.o: event_loop.c sqe.h
	cc -c $(CFLAGS) -o event_loop.o event_loop.c

carp.o: carp.c sqe.h
	cc -c $(CFLAGS) -o carp.o carp.c

opts.o: opts.c sqe.h
	cc -c $(CFLAGS) -o opts.o opts.c

util.o: util.c sqe.h
	cc -c $(CFLAGS) -o util.o util.c

client_input.o: client_input.c sqe.h
	cc -c $(CFLAGS) -o client_input.o client_input.c

client_listen.o: client_listen.c sqe.h
	cc -c $(CFLAGS) -o client_listen.o client_listen.c

destination.o: destination.c sqe.h
	cc -c $(CFLAGS) -o destination.o destination.c

client_requests_info.o: client_requests_info.c sqe.h
	cc -c $(CFLAGS) -o client_requests_info.o client_requests_info.c

test_ber: test_ber.c $(STDOBJ)
	cc $(CFLAGS) -o test_ber test_ber.c $(STDLINK)

test_msgpack: test_msgpack.c $(STDOBJ)
	cc $(CFLAGS) -o test_msgpack test_msgpack.c $(STDLINK)

test: snmp-query-engine
	prove t/queries.t

test-details: snmp-query-engine
	perl t/queries.t
