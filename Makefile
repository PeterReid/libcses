CC=gcc
CFLAGS=-Wall -Wextra -pedantic

SOURCES=src/conn.c src/server.c src/crypter.c src/memzero.c
TEST_SOURCES=src/test/all.c src/test/rng.c

test:
	gcc $(CFLAGS) -g -o tester -I src/include $(SOURCES) $(TEST_SOURCES) -lsodium

valgrind: test
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./tester

