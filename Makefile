test:
	gcc -Wall -Wextra -pedantic -g -o tester -I src/include  src/test/all.c src/test/rng.c src/conn.c src/server.c src/crypter.c src/memzero.c -lsodium

