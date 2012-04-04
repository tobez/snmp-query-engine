all: snmp-query-engine

snmp-query-engine: main.o
	cc -g -O3 -o snmp-query-engine main.o

test: test.c
	cc -g -Wall -Werror -O3 -o test test.c && ./test
