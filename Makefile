test:
	gcc -Wall -g -o tester -I src/include  src/test/all.c src/conn.c src/server.c src/secret_box.c src/salsa.c src/memzero.c -lsodium

