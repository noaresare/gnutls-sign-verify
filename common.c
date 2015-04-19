
#include <gnutls/abstract.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

/*
 * Allocate a buffer and read the contents of the file pointed to by path
 * into it. If size 0, the full file is read, else size number of bytes
 * will be read.
 */
gnutls_datum_t read_to_buffer(char *path, int size) {
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
