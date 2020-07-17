/* 
   This is an example C program using LekKit' SHA256 library
   (https://github.com/LekKit/sha256)
   
   Produces a hash for a given file, much like sha256sum CLI utility
*/

#include "sha256.h"
#include <stdio.h>

int main(int argc, char** argv){
    if (argc < 2){
        printf("Usage: %s [file]\n", argv[0]);
        return 0;
    }
    FILE* file = fopen(argv[1], "rb");
    if (!file){
        printf("Cannot open file\n");
        return 0;
    }
    char buffer[1024];
    size_t size;
    struct sha256_buff buff;
    sha256_init(&buff);
    while (!feof(file)){
        /* Hash file by 1kb chunks, instead of loading into RAM at once */
        size = fread(buffer, 1, 1024, file);
        sha256_update(&buff, buffer, size);
    }
    char hash[65] = {0}; /* hash[64] is null-byte */
    sha256_finalize(&buff);
    sha256_read_hex(&buff, hash);
    printf("%s\n", hash);
    return 0;
}
