/* Ken Sheedlo
 * leetfs Encrypted File System
 * CSCI 3753 P.A. 5
 *
 * File: cryptio.c
 * Implementation of high-level encrypted I/O.
 */

#include "cryptio.h"

int cryptio_initctx(EVP_CIPHER_CTX *ctx, const char *key, int action){
    int i;
    unsigned char key_data[32];
    unsigned char iv[32];

    if(key == NULL){
        fprintf(stderr, "cryptio_initctx: key must not be NULL\n");
        return 0;
    }

    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, 
            (const unsigned char *)key, strlen(key), 5, key_data, iv);
    if(i != 32){
        fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
        return 0;
    }
    /* Init Engine */
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)key, 
        iv, action);
    return 1;
}

int cryptio_read(EVP_CIPHER_CTX *ctx, FILE *input, void *buf, size_t bytes, 
                    int action, int *outlen){
    void *inbuf = alloca(bytes);
    size_t inlen = fread(inbuf, 1, bytes, input);
    if(inlen > 0){
        if(action >= 0){
            if(!EVP_CipherUpdate(ctx, buf, outlen, inbuf, inlen)){
                /* Error */
                EVP_CIPHER_CTX_cleanup(ctx);
                return 0;
            }
        }else{
            memcpy(buf, inbuf, inlen);
            *outlen = inlen;
        }
        return 1;
    }else{
        /* EOF */   
        if(action >= 0){
            EVP_CipherFinal_ex(ctx, buf, outlen);
            EVP_CIPHER_CTX_cleanup(ctx);
        }else{
            *outlen = 0;
        }
        return 0;
    }
}

int cryptio_write(EVP_CIPHER_CTX *ctx, FILE *output, void *data, size_t bytes,
                    int action){
    void *outbuf = alloca(bytes);
    int outlen;
    if(action >= 0){
        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, data, bytes)){
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            return 0;
        }
    }else{
        memcpy(outbuf, data, bytes);
        outlen = bytes;
    }
    int writelen = fwrite(outbuf, 1, bytes, output);
    if(writelen != outlen){
            /* Error */
            perror("fwrite error");
            EVP_CIPHER_CTX_cleanup(ctx);
            return 0;
    }
    return 1;
}

void *cryptio_mapread(const char *key, FILE* input, int action, int *outlen, 
        size_t lenreq){
    EVP_CIPHER_CTX ctx;
    cryptio_initctx(&ctx, key, action);

    int inlen;
    if(fseek(input, 0, SEEK_END)){
        EVP_CIPHER_CTX_cleanup(&ctx);
        return NULL;
    }
    inlen = ftell(input);
    rewind(input);

    size_t bufsize = (((unsigned)inlen + BLOCKSIZE) < lenreq ? lenreq : 
                        ((unsigned)inlen) + BLOCKSIZE);
#if 0
    void *outmap = mmap(NULL, inlen + BLOCKSIZE, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    void *inmap = mmap(NULL, inlen, PROT_READ, MAP_PRIVATE, inputfd, 0);
    if(outmap == MAP_FAILED || inmap == MAP_FAILED){
        return NULL;
    }
#endif
    unsigned char *outmap = malloc(bufsize);
    unsigned char *inmap = malloc(inlen);
    if(outmap == NULL || inmap == NULL){
        return NULL;
    }
    fread(inmap, 1, inlen, input);

    size_t acc;
    unsigned char *outbuf = outmap;
    if(action >= 0){
        if(!EVP_CipherUpdate(&ctx, outbuf, outlen, inmap, inlen)){
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return NULL;
        }   
        acc = *outlen;
        outbuf += *outlen;
        if(!EVP_CipherFinal_ex(&ctx, outbuf, outlen)){
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return NULL;
        }   
        *outlen += acc;
    }else{
        memcpy(outmap, inmap, inlen);
        *outlen = inlen;
    }
    free(inmap);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outmap;
}

int cryptio_mapwrite(const char *key, FILE* output, void *data, size_t bytes, 
        int action){
    EVP_CIPHER_CTX ctx;
    cryptio_initctx(&ctx, key, action);
    
#if 0
    void *outmap = mmap(NULL, bytes + BLOCKSIZE, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE, outputfd, 0);
    if(outmap == MAP_FAILED){
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
#endif
    void *outmap = malloc(bytes + BLOCKSIZE);
    if(!outmap){
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }

    int outlen;
    int acc = 0;
    void *outbuf = outmap;
    if(action >= 0){
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, data, bytes)){
            /* Error */
            free(outmap);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        outbuf += outlen;
        acc += outlen;
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)){
            /* Error */
            free(outmap);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        acc += outlen;
    }else{
        memcpy(outmap, data, bytes);
        acc = bytes;
    }
    fwrite(outmap, 1, acc, output);
    free(outmap);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return acc;
}

int cryptio_bsread(const char *key, FILE *input, bytestream_t *output, int action){
    /* Buffers */
    unsigned char inbuf[BLOCKSIZE];
    int inlen;
    int outlen;
    int writelen;
    /* Allow enough space in output buffer for additional cipher block */
    unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX ctx;

    if(action >= 0){
        cryptio_initctx(&ctx, key, action);
    }

    /* Loop through Input File*/
    for(;;){
        /* Read Block */
        inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, input);
        if(inlen <= 0){
            /* EOF -> Break Loop */
            break;
        }

        /* If in cipher mode, perform cipher transform on block */
        if(action >= 0){
            if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
        /* If in pass-through mode. copy block as is */
        else{
            memcpy(outbuf, inbuf, inlen);
            outlen = inlen;
        }

        /* Write Block */
        writelen = (int)bs_write(outbuf, sizeof(*outbuf), outlen, output);
        if(writelen != outlen){
            /* Error */
            perror("fwrite error");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    } /* end for */

    /* If in cipher mode, handle necessary padding */
    if(action >= 0){
        /* Handle remaining cipher block + padding */
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        /* Write remainign cipher block + padding*/
        bs_write(outbuf, sizeof(*inbuf), outlen, output);
        EVP_CIPHER_CTX_cleanup(&ctx);
    }

    /* Success */
    return 1;
}

int cryptio_bswrite(const char *key, bytestream_t *input, FILE *output, int action){
    /* Buffers */
    unsigned char inbuf[BLOCKSIZE];
    int inlen;
    int outlen;
    int writelen;
    /* Allow enough space in output buffer for additional cipher block */
    unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX ctx;

    if(action >= 0){
        cryptio_initctx(&ctx, key, action);
    }

    /* Loop through Input File*/
    for(;;){
        /* Read Block */
        inlen = (int)bs_read(inbuf, sizeof(*inbuf), BLOCKSIZE, input);
        if(inlen <= 0){
            /* EOF -> Break Loop */
            break;
        }

        /* If in cipher mode, perform cipher transform on block */
        if(action >= 0){
            if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
            }
        }
        /* If in pass-through mode. copy block as is */
        else{
            memcpy(outbuf, inbuf, inlen);
            outlen = inlen;
        }

        /* Write Block */
        writelen = fwrite(outbuf, sizeof(*outbuf), outlen, output);
        if(writelen != outlen){
            /* Error */
            perror("fwrite error");
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
    } /* end for */

    /* If in cipher mode, handle necessary padding */
    if(action >= 0){
        /* Handle remaining cipher block + padding */
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        /* Write remainign cipher block + padding*/
        fwrite(outbuf, sizeof(*inbuf), outlen, output);
        EVP_CIPHER_CTX_cleanup(&ctx);
    }

    /* Success */
    return 1;
}

