/* Ken Sheedlo
 * Bytestream Data Type
 *
 * Defines a file-like byte stream in memory that can be read from and written
 * to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BS_BLOCKSIZE    4096

#define BS_SEEK_SET     0
#define BS_SEEK_END     1

typedef struct {
    char *data;
    char *read;
    size_t length;
    size_t max_length;
} bytestream_t;

int32_t bs_init(bytestream_t *stream);

size_t bs_read(void *ptr, size_t size, size_t nmemb, bytestream_t *stream);

size_t bs_write(const void *ptr, size_t size, size_t nmemb, bytestream_t *stream);

void bs_seek(bytestream_t *stream, int seek);

void bs_delete(bytestream_t *stream);
