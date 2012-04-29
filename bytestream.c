/* Ken Sheedlo
 * Bytestream Implementation */

#include "bytestream.h"

int32_t bs_init(bytestream_t *stream){
    void *d = malloc(BS_BLOCKSIZE);
    if(d == NULL){
        return 0;
    }
    stream->data = d;
    stream->read = d;
    stream->length = 0;
    stream->max_length = BS_BLOCKSIZE;
    return 1;
}

size_t bs_read(void *ptr, size_t size, size_t nmemb, bytestream_t *stream){
    size_t read_size = size * nmemb;   
    if(stream->read + read_size > stream->data + stream->length){
        /* Adjust the read size */
        read_size = (stream->data + stream->length) - stream->read;
    }
    memcpy(ptr, stream->read, read_size);
    stream->read += read_size;
    return read_size;
}

size_t bs_write(const void *ptr, size_t size, size_t nmemb, bytestream_t *stream){
    size_t write_size = size * nmemb;
    char *new_end = stream->read + write_size;      
    size_t new_size = stream->max_length;
    while(new_end >= (stream->data + new_size)){
        new_size <<= 1;
    }
    if(new_size > stream->max_length){
        int read_diff = stream->read - stream->data;
        char *new_data = realloc(stream->data, new_size);
        if(new_data == NULL){
            return 0;
        }
        stream->data = new_data;
        stream->read = stream->data + read_diff;
    }
    memcpy(stream->read, ptr, write_size);
    stream->read += write_size;

    if(stream->read > stream->data + stream->length){
        stream->length = stream->read - stream->data;
    }
    return write_size;
}

void bs_seek(bytestream_t *stream, int seek){
    stream->read = stream->data;
    if(seek == BS_SEEK_END){
        stream->read = stream->data + stream->length;
    }
}

void bs_delete(bytestream_t *stream){
    free(stream->data);
    stream->read = NULL;
    stream->length = 0;
    stream->max_length = 0;
}
