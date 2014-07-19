test:
	gcc -g -o tester -I src/include  src/test/all.c src/conn.c src/secret_box.c src/salsa.c src/memzero.c -lnacl

