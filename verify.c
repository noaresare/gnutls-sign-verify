
#include <gnutls/abstract.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

gnutls_datum_t read_to_buffer(char *path, int size);

static int get_pubkey(char *path, gnutls_pubkey_t *key) {
  int i;
  gnutls_datum_t key_buf;

  key_buf = read_to_buffer(path, 0);

    
  if ((i = gnutls_pubkey_import(*key, &key_buf, GNUTLS_X509_FMT_PEM))) {
    fprintf(stderr, "Failed to call gnutls_pubkey_import(): %s\n", gnutls_strerror(i));
    return 1;
  }

  return 0;
}

int main(int argc, char **argv) {

  gnutls_pubkey_t pubkey;
  gnutls_datum_t challenge;
  gnutls_datum_t signature;
  int i;
  

  if (gnutls_pubkey_init(&pubkey)) {
    fprintf(stderr, "gnutls_pubkey_init failed\n");
    return 1;
  }
  

  if (get_pubkey("pubkey.pem", &pubkey)) {
    fprintf(stderr, "get_pubkey() failed, exiting\n");
    return 2;
  }

  challenge = read_to_buffer("challenge.bin", 0);
  signature = read_to_buffer("signature.bin", 0);

  i = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256, 0, &challenge, &signature);
  if (i < 0) {
    fprintf(stderr, "Failed to call gnutls_pubkey_verify_data2(): %s\n", gnutls_strerror(i));
    return 1;
  } else {
    printf("verification succeeded\n");
  }



  printf("at the end of program\n");

  

  return 0;
}
