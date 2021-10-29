#ifdef __unix__ // __unix__ is usually defined by compilers targeting Unix systems
# include <unistd.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <resolv.h>
# define SOCKLEN_T socklen_t
# define CLOSESOCKET close
#elif defined _WIN32 // _Win32 is usually defined by compilers targeting 32 or 64 bit Windows systems
# include <windows.h>
# include <winsock2.h>
# define SOCKLEN_T int
# define CLOSESOCKET closesocket
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#ifdef _WIN32
WSADATA wsa; // Winsock data
#endif


int create_client(const char *ip, int port){
  int sock;
  struct sockaddr_in confsock;
  #ifdef _WIN32
  WSAStartup(MAKEWORD(2,0), &wsa);
  #endif
  sock = socket(AF_INET, SOCK_STREAM, 0);
  memset(&confsock, 0, sizeof(confsock));
  confsock.sin_family = AF_INET;
  confsock.sin_port = htons(port);
  confsock.sin_addr.s_addr = inet_addr(ip);
  while (connect(sock, (struct sockaddr *)&confsock, sizeof(confsock)) != 0) {
    /* do nothing*/
  }
  return sock;
}

unsigned char *routine(SSL *ssl){
  int len;
  char buff[1024];
  char *msg = "Key received \n";
  //TODO : add reponse with hostname
  do {
    len = SSL_read(ssl, buff, sizeof(buff)-1);
    buff[len+1] = '\0';
  } while(len != 32);
  buff[32] = '\0';
  SSL_write(ssl, msg, strlen(msg));
  sleep(0.05);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  int sock = SSL_get_fd(ssl);
  CLOSESOCKET(sock);
  return (unsigned char *)strdup(buff);
}

unsigned char *get_key(char *ip, int port){
  int sock = create_client(ip, port);
  char buff[1024] = {0};
  //init ssl ctx
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) {
    puts("[-] Can't create ssl ctx");
    exit(1);
  }
  SSL *ssl;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  if (SSL_connect(ssl) == -1) {
    exit(1);
  }
  while (SSL_connect(ssl) == -1) {
    /* do nothing */
  }
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  unsigned char *out = routine(ssl);
  SSL_CTX_free(ctx);
  return out;
}
