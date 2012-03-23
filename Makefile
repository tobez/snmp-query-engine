all: test

test: test.c
	cc -g -Wall -Werror -O3 -o test test.c
