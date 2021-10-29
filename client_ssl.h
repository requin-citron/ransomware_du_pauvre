#ifndef __CLIENT_SSL__
#define __CLIENT_SSL__

int create_client(const char *, int);
unsigned char *routine(SSL *);
unsigned char *get_key(char *, int);
#endif
