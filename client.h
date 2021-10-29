#ifndef __CLIENT__
#define __CLIENT__

void walk_like_cowboy(const char* , unsigned char *);
int encrypt_buff(unsigned char *, int , unsigned char *, unsigned char *, unsigned char *);
void encrypt_file(const char *, unsigned char *);
void encrypt_dir(int, const char **, unsigned char *);
#endif
