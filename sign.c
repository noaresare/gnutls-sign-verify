
#include <gnutls/abstract.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#define TPM_KEY_URL "tpmkey:uuid=5014ce3f-aab4-4ab6-83ac-572b7bd33654;storage=user"
#define TPM_SRK_PASSWORD "a"

gnutls_datum_t read_to_buffer(char *path, int size);

static int get_key(char *url, gnutls_privkey_t *key) {
  int i;
  if ((i = gnutls_privkey_import_tpm_url(*key, url, TPM_SRK_PASSWORD, NULL, 0))) {
    fprintf(stderr, "Failed to call gnutls_privkey_import_url(): %s\n", gnutls_strerror(i));
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
  gnutls_datum_t challenge;
  gnutls_datum_t signature;
  int i;
  

  if (gnutls_privkey_init(&key)) {
    fprintf(stderr, "privkey init failed\n");
    return 1;
  }

  if (get_key(TPM_KEY_URL, &key)) {
    fprintf(stderr, "get_key() failed, exiting\n");
    return 2;
  }
    
  challenge = read_to_buffer("/dev/urandom", 32);
  if (challenge.size == 0) {
    fprintf(stderr, "read_to_buffer from /dev/urandom failed, exiting");
    return 3;
  }
  
  write_data_to_file("challenge.bin", challenge);
  printf("Wrote challenge.bin to file\n");

  if ((i = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &challenge, &signature))) {
    fprintf(stderr, "Failed to call gnutls_privkey_sign_data(): %s\n", gnutls_strerror(i));
    return 1;
  }

  write_data_to_file("signature.bin", signature);
  printf("Wrote signature.bin to file\n");



  printf("at the end of program\n");

  

  return 0;
}
