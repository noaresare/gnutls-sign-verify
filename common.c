
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

int write_data_to_file(char *path, gnutls_datum_t data) {
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


