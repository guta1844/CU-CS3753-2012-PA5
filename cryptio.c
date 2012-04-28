/* Ken Sheedlo
 * leetfs Encrypted File System
 * CSCI 3753 P.A. 5
 *
 * File: cryptio.c
 * Implementation of high-level encrypted I/O.
 */

int cryptio_initctx(EVP_CIPHER_CTX *ctx, unsigned char *key, int action){
    int i;
    unsigned char key_data[32];
    unsigned char iv[32];

    if(key == NULL){
        fprintf(stderr, "cryptio_initctx: key must not be NULL\n");
        return 0;
    }

    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key, strlen(key),
            5, key_data, iv);
    if(i != 32){
        fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
        return 0;
    }
    /* Init Engine */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv, action);
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
                EVP_CIPHER_CTX_cleanup(&ctx);
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
            EVP_CIPHER_CTX_cleanup(&ctx);
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
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
    }
    return 1;
}

void *cryptio_mapread(const char *key, int inputfd, int action, size_t *outlen, 
        size_t lenreq){
    EVP_CIPHER_CTX ctx;
    cryptio_initctx(&ctx, key, action);

    off_t inlen = lseek(input, 0, SEEK_END);
    rewind(input);

    inlen = (inlen < lenreq ? lenreq : inlen);
    void *outmap = mmap(NULL, inlen + BLOCKSIZE, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0);
    void *inmap = mmap(NULL, inlen, PROT_READ, MAP_PRIVATE, inputfd, 0);
    if(outmap == MAP_FAILED || inmap == MAP_FAILED){
        return NULL;
    }

    size_t acc;
    void *outbuf = outmap;
    if(action >= 0){
        if(!EVP_CipherUpdate(&ctx, outbuf, outlen, inmap, inlen)){
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return NULL;
        }   
        acc = *outlen;
        outbuf += *outlen;
        if(!EVP_CipherFinal_ex(&ctx, outbuf, outlen, inmap, inlen)){
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return NULL;
        }   
        *outlen += acc;
    }else{
        memcpy(outmap, inmap, inlen);
        *outlen = inlen;
    }
    munmap(inmap, inlen);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outmap;
}

int cryptio_mapwrite(const char *key, int outputfd, void *data, size_t bytes, 
        int action){
    EVP_CIPHER_CTX ctx;
    cryptio_initctx(&ctx, key, action);
    
    void *outmap = mmap(NULL, bytes + BLOCKSIZE, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE, outputfd, 0);
    if(outmap == MAP_FAILED){
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }

    int outlen;
    int acc = 0;
    void *outbuf = outmap;
    if(action >= 0){
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, data, bytes)){
            /* Error */
            munmap(outmap, bytes + BLOCKSIZE);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        outbuf += outlen;
        acc += outlen;
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)){
            /* Error */
            munmap(outmap, bytes + BLOCKSIZE);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        acc += outlen;
    }else{
        memcpy(outmap, inmap, bytes);
        acc = bytes;
    }
    munmap(outmap, acc);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return acc;
}
