
#include <gnutls/abstract.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/*
 * Allocate a buffer and read the contents of the file pointed to by path
 * into it. If size 0, the full file is read, else size number of bytes
 * will be read.
 */
static gnutls_datum_t read_to_buffer(char *path, int size) {
  struct stat sb;
  unsigned char *buf;
  gnutls_datum_t out = {0};
  FILE *fp;
  size_t read_size;

  if (size == 0) {
    if (stat(path, &sb)) {
      perror("failed to stat()");
    }
    printf("Detected file size is %ld\n", sb.st_size);
    size = sb.st_size;
  } 

  buf = malloc(size);
  if (buf == NULL) {
    perror("failed to malloc()");
    return out;
  }

  fp = fopen(path, "r");
  if (fp == NULL) {
    perror("failed to fopen()");
    return out;
  }

  read_size = fread(buf, sizeof(char), size, fp);
  if (read_size < size) {
    fprintf(stderr, "Read %ld bytes\n", read_size);
    perror("short fread()");
    return out;
  }
  if (fclose(fp)) {
    perror("failed to fclose()");
    return out;
  }
  out.size = size;
  out.data = buf;
  return out;
}

static int get_key(char *path, gnutls_privkey_t *key) {
  gnutls_x509_privkey_t x509_key;
  int i;
  unsigned int bits;
  gnutls_datum_t key_buf = read_to_buffer(path, 0);

  if ((i = gnutls_x509_privkey_init(&x509_key))) {
    fprintf(stderr, "Failed to call gnutls_x509_privkey_init(): %s\n", gnutls_strerror(i));
    return 1;
  }
    
  if ((i = gnutls_x509_privkey_import(x509_key, &key_buf, GNUTLS_X509_FMT_PEM))) {
    fprintf(stderr, "Failed to call gnutls_x509_privkey_import(): %s\n", gnutls_strerror(i));
    return 1;
  }

  free(key_buf.data);
    
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


  return 0;
}

static int write_data_to_file(char *path, gnutls_datum_t data) {
  size_t bytes_written;
  FILE *f;

  f = fopen(path, "w");
  if (f == NULL) {
    perror("failed to fopen()");
    return 1;
  }

  bytes_written = fwrite(data.data, 1, data.size, f);
  if (bytes_written < data.size) {
    fprintf(stderr, "Wrote %ld bytes\n", bytes_written);
    perror("failed to fwrite()");
    return 1;
  }

  fclose(f);

  return 0;
}

int main(int argc, char **argv) {

  gnutls_privkey_t key;
  gnutls_pubkey_t pubkey;
  gnutls_datum_t challenge;
  gnutls_datum_t signature;
  int i;
  unsigned int mandatory;
  gnutls_digest_algorithm_t preferred_algo;
  

  if (gnutls_privkey_init(&key)) {
    fprintf(stderr, "privkey init failed\n");
    return 1;
  }

  if (gnutls_pubkey_init(&pubkey)) {
    fprintf(stderr, "gnutls_pubkey_init failed\n");
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

  challenge = read_to_buffer("/dev/urandom", 32);
  if (challenge.size == 0) {
    fprintf(stderr, "read_to_buffer from /dev/urandom failed, exiting");
    return 3;
  }
  
  write_data_to_file("challenge.bin", challenge);

  if ((i = gnutls_pubkey_import_privkey(pubkey, key, GNUTLS_KEY_DIGITAL_SIGNATURE, 0))) {
    fprintf(stderr, "Failed to call gnutls_pubkey_import_privkey(): %s\n", gnutls_strerror(i));
    return 1;
  }

  if ((i = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &preferred_algo, &mandatory))) {
    fprintf(stderr, "Failed to call gnutls_pubkey_get_preferred_hash_algorithm(): %s\n", gnutls_strerror(i));
    return 1;
  }

  if ((i = gnutls_privkey_sign_data(key, preferred_algo, 0, &challenge, &signature))) {
    fprintf(stderr, "Failed to call gnutls_privkey_sign_data(): %s\n", gnutls_strerror(i));
    return 1;
  }

  
  // TODO: don't hardcode sign algorithm
  i = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256, 0, &challenge, &signature);
  if (i < 0) {
    fprintf(stderr, "Failed to call gnutls_pubkey_verify_data2(): %s\n", gnutls_strerror(i));
    return 1;
  } else {
    printf("verification succeeded\n");
  }

  write_data_to_file("signature.bin", signature);



  printf("at the end of program\n");

  

  return 0;
}
