CC=gcc
CFLAGS = -I . -lcrypto -lssl
RM=rm

all: client server
client: client.c client_ssl.o
		$(CC) -o client $^ $(CFLAGS)
client.o:client.c client.h
		$(CC) -c $<
client_ssl.o:client_ssl.c client_ssl.h
		$(CC) -c $<
server: server.c
		$(CC) -o server server.c $(CFLAGS)
clean:
		$(RM) *.o
		$(RM) server
		$(RM) client
