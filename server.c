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


int create_server(int port){
  int sock;
  struct sockaddr_in confsock;
  #ifdef _WIN32
  WSAStartup(MAKEWORD(2,0), &wsa);
  #endif
  sock = socket(AF_INET, SOCK_STREAM, 0);
  memset(&confsock, 0, sizeof(confsock));
  confsock.sin_family = AF_INET;
  confsock.sin_port = htons(port);
  confsock.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&confsock, sizeof(confsock)) != 0){ printf("[-] %d Port may already used\n", port);
  exit(1);
}
  if (listen(sock, 10) != 0){
    puts("[-] Can't listen");
    exit(1);
  }
  puts("[+] Server is up");
  return sock;
}

void routine(SSL *ssl, unsigned char *key){
  char buff[1024];
  int len;
  if(SSL_accept(ssl) == -1){
    puts("[-] connection ssl error");
    exit(1);
  }
  printf("[+] Cypher used : %s\n", SSL_get_cipher(ssl));
  SSL_write(ssl, key, strlen(key));
  do {
    len = SSL_read(ssl, buff, sizeof(buff)-1);
    buff[len+1] = '\0';
  } while(len == 1023);
  int sock = SSL_get_fd(ssl);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  CLOSESOCKET(sock);
  return;
}


void load_keys(SSL_CTX *ctx, const char *certFile, const char *keyFile){
  // The server private key in PEM format, if internals required
  if(SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
  SSL_CTX_use_RSAPrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0){
    puts("[-] failed to load cert and key");
    exit(1);
  }
  // verify private key match the public key into the certificate
  if(!SSL_CTX_check_private_key(ctx)){
  puts("[-] Private key does not match the public certificate...");
  } else
  puts("[+] Server's private key match public certificat !");
  return;
}

unsigned char *key_gen(void){
  unsigned char *charset = "azertyuiopqsdfghjklmwxcvbn1234567890@/&#";
  size_t charset_len = strlen(charset);
  unsigned char out[32] = {0};
  //gen 32 key
  for (size_t i = 0; i < 32; i++) {
    out[i] = charset[rand() % charset_len];
  }
  out[32] = '\0';
  return strdup(out);
}

int main(int argc, char const *argv[]) {
  if (argc < 2) {
    printf("%s port\n", argv[0]);
    return 0;
  }
  puts("New instance");
  srand(time(NULL));

  unsigned int port = atoi(argv[1]);
  int sock = create_server(port);
  //init ctx;
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL) {
    puts("[-] Can't create ssl ctx");
    exit(1);
  }
  //create key
  puts("Copy past your key");
  unsigned char *key = key_gen();
  printf("[+] Key is: %s\n", key);

  //load cert
  load_keys(ctx, "./keyring/cert.pem", "./keyring/key.pem");
  while (true){
    struct sockaddr_in addr;
    SOCKLEN_T taille = sizeof(addr);
    int client = accept(sock, (struct sockaddr*) &addr, &taille);
    printf("[+] Connection [%s:%d]\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    routine(ssl, key);
  }
  SSL_CTX_free(ctx);
  CLOSESOCKET(sock);
  return 0;
}
