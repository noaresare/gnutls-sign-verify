
#include <gnutls/abstract.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int get_key(char *path, gnutls_privkey_t *key) {
  struct stat sb;
  unsigned char *buf;
  FILE *key_file;
  size_t read_count;
  gnutls_datum_t datum;
  gnutls_x509_privkey_t x509_key;
  int i;
  unsigned int bits;

  if (stat(path, &sb)) {
    perror("failed to stat()");
    return 1;
  }
  printf("Key size is %ld\n", sb.st_size);

  buf = malloc(sb.st_size);
  if (buf == NULL) {
    perror("failed to malloc()");
    return 1;
  }

  key_file = fopen(path, "r"); 
  if (key_file == NULL) {
    perror("failed to fopen()");
    return 1;
  }
    
  read_count = fread(buf, sizeof(char), sb.st_size, key_file);
  if (read_count < sb.st_size) {
    fprintf(stderr, "Read %ld bytes\n", read_count);
    perror("short fread()");
    return 1;
  }
  if (fclose(key_file)) {
    perror("failed to fclose()");
    return 1;
  }

  datum.data = buf;
  datum.size = sb.st_size;

  if ((i = gnutls_x509_privkey_init(&x509_key))) {
    fprintf(stderr, "Failed to call gnutls_x509_privkey_init(): %s\n", gnutls_strerror(i));
    return 1;
  }
    
  if ((i = gnutls_x509_privkey_import(x509_key, &datum, GNUTLS_X509_FMT_PEM))) {
    fprintf(stderr, "Failed to call gnutls_x509_privkey_import(): %s\n", gnutls_strerror(i));
    return 1;
  }

  free(buf);
    
  i = gnutls_x509_privkey_get_pk_algorithm2(x509_key, &bits); 
  if (i < 0) {
    fprintf(stderr, "Failed to call gnutls_x509_privkey_get_pk_algorithm2(): %s\n", gnutls_strerror(i));
    return 1;
  }
 
  printf("Private key has exponent %d bits of size\n", bits);

  if ((i = gnutls_privkey_import_x509(*key, x509_key, 0))) {
    fprintf(stderr, "Failed to call gnutls_privkey_import_x509(): %s\n", gnutls_strerror(i));
    return 1;
  }

  gnutls_x509_privkey_deinit(x509_key);

  return 0;
}

int main(int argc, char **argv) {

  gnutls_privkey_t key;

  if (gnutls_privkey_init(&key)) {
    fprintf(stderr, "privkey init failed\n");
    return 1;
  }
  
/*
  if (gnutls_privkey_import_url(key, "testkey-private.pem", 0)) {
    fprintf(stderr, "gnutls_privkey_import_url() failed\n");
    return 1;
  }
*/
  if (get_key("testkey-private.pem", &key)) {
    return 2;
  }

  printf("at the end of program\n");


  return 0;
}
