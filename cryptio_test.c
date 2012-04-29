/* cryptio_test.c
 * Ken Sheedlo
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cryptio.h"

#define FAILURE 0
#define SUCCESS 1

int do_crypt(FILE* input, FILE* output, int action, const char *key){
    int read_action = (action == CRYPTIO_DECRYPT ? action : CRYPTIO_PASSTHRU);
    int write_action = (action == CRYPTIO_ENCRYPT ? action : CRYPTIO_PASSTHRU);
    bytestream_t stream;
    bs_init(&stream);

    if(!cryptio_bsread(key, input, &stream, read_action)){
        bs_delete(&stream);
        return FAILURE;
    }
    bs_seek(&stream, BS_SEEK_SET);
    if(!cryptio_bswrite(key, &stream, output, write_action)){
        return FAILURE;
    }

    bs_delete(&stream);
    return SUCCESS;
#if 0
    if(action == CRYPTIO_ENCRYPT){
        int outlen;
        void *data = cryptio_mapread(key, input, CRYPTIO_PASSTHRU, &outlen, 0);
        if(data == NULL){
            return FAILURE;
        }
        if(!cryptio_mapwrite(key, output, data, outlen, action)){
            return FAILURE;
        }
        free(data);
    }else if(action == CRYPTIO_DECRYPT){
        int outlen;
        void *data = cryptio_mapread(key, input, action, &outlen, 0);
        if(data == NULL){
            return FAILURE;
        }
        if(!cryptio_mapwrite(key, output, data, outlen, CRYPTIO_PASSTHRU)){
            return FAILURE;
        }
        free(data);
    }else{
        /* CRYPTIO_PASSTHRU */
        off_t size = lseek(input, 0, SEEK_END);
        lseek(input, 0, SEEK_SET);

        void *indata = mmap(NULL, size, PROT_READ, MAP_PRIVATE, input, 0);
        void *outdata = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, 
                            output, 0);
        if(indata == NULL || outdata == NULL){
            return FAILURE;
        }
        memcpy(outdata, indata, size);
        munmap(indata, size);
        munmap(outdata, size);
    }
    return SUCCESS;
#endif
}

int main(int argc, char **argv){

    /* Local vars */
    int action = 0;
    int ifarg;
    int ofarg;
    FILE* input = NULL;
    FILE* output = NULL;
    char* key_str = "douche";
    
    if(argc < 3){
	fprintf(stderr, "usage: %s %s\n", argv[0],
		"<type> <opt key phrase> <in path> <out path>");
	exit(EXIT_FAILURE);
    }

    /* Encrypt Case */
    if(!strcmp(argv[1], "-e")){
	/* Check Args */
	if(argc != 5){
	    fprintf(stderr, "usage: %s %s\n", argv[0],
		    "-e <key phrase> <in path> <out path>");
	    exit(EXIT_FAILURE);
	}
	/* Set Vars */
	key_str = argv[2];
	ifarg = 3;
	ofarg = 4;
	action = 1;
    }
    /* Decrypt Case */
    else if(!strcmp(argv[1], "-d")){
	/* Check Args */
	if(argc != 5){
	    fprintf(stderr, "usage: %s %s\n", argv[0],
		    "-d <key phrase> <in path> <out path>");
	    exit(EXIT_FAILURE);
	}
	/* Set Vars */
	key_str = argv[2];
	ifarg = 3;
	ofarg = 4;
	action = 0;
    }
    /* Pass-Through (Copy) Case */
    else if(!strcmp(argv[1], "-c")){
	/* Check Args */
	if(argc != 4){
	    fprintf(stderr, "usage: %s %s\n", argv[0],
		    "-c <in path> <out path>");
	    exit(EXIT_FAILURE);
	}
	/* Set Vars */
	ifarg = 2;
	ofarg = 3;
	action = -1;
    }
    /* Bad Case */
    else {
	fprintf(stderr, "Unkown action\n");
	exit(EXIT_FAILURE);
    }

    /* Open Files */
    input = fopen(argv[ifarg], "rb");
    if(input == NULL){
	perror("infile open error");
	return EXIT_FAILURE;
    }
    output = fopen(argv[ofarg], "wb+");
    if(output == NULL){
	perror("outfile open error");
	return EXIT_FAILURE;
    }
    
    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(input, output, action, key_str)){
	fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(output)){
        perror("output close error\n");
    }
    if(fclose(input)){
	perror("input close error\n");
    }

    return EXIT_SUCCESS;
}
