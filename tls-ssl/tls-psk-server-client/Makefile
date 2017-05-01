CFLAGS=-I..  -DOPENSSL_NO_ENGINE -Wall -Wextra
all: psk_client psk_server
psk_client: psk_client.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto -lssl
psk_server:psk_server.c #s_cb.c 
	gcc $(CFLAGS) -o $@ $^ -lcrypto -lssl
clean:
	rm -f psk_server psk_client
