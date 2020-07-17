/* 
   This is a test vector suite for LekKit' SHA256 library
   (https://github.com/LekKit/sha256)
   
   Used sources:
   https://www.di-mgt.com.au/sha_testvectors.html
   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
*/

#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>

void test_str(const char* in, const char* out) {
    static size_t test_count = 0;
    
    char buffer[65] = {0};
    sha256_easy_hash_hex(in, strlen(in), buffer);
    if (strcmp(out, buffer) != 0) {
        printf("String test #%i failed!!!\nsha256(\"%s\") = \"%s\"\nExpected value: \"%s\"\n\n", test_count, in, buffer, out);
        printf("Please report this issue to https://github.com/LekKit/sha256\n");
        exit(0);
    } else {
        printf("String test #%i passed\nsha256(\"%s\") = \"%s\"\n\n", test_count, in, buffer);
    }
    
    test_count++;
}

void test_bytes(char byte, size_t size, const char* out) {
    static size_t test_count = 0;
    
    char buffer[1024];
    struct sha256_buff buff;
    size_t tmp_size = size;
    memset(buffer, byte, 1024);
    sha256_init(&buff);
    
    while (tmp_size >= 1024) {
        sha256_update(&buff, buffer, 1024);
        tmp_size -= 1024;
    }
    sha256_update(&buff, buffer, size % 1024);
    sha256_finalize(&buff);
    
    sha256_read_hex(&buff, buffer);
    buffer[64] = 0;
    
    if (strcmp(out, buffer) != 0) {
        printf("Byte test #%i failed!!!\nsha256(0x%X * %u) = \"%s\"\nExpected value: \"%s\"\n\n", test_count, byte, size, buffer, out);
        printf("Please report this issue to https://github.com/LekKit/sha256\n");
        exit(0);
    } else {
        printf("Byte test #%i passed\nsha256(0x%X * %u) = \"%s\"\n\n", test_count, byte, size, buffer);
    }
    
    test_count++;
}

int main() {
    test_str("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    test_str("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    test_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    test_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", "2ff100b36c386c65a1afc462ad53e25479bec9498ed00aa5a04de584bc25301b");
    test_str("LekKit", "500f94082c97ab2c1188e53d9f467a9e73bfb366e7309adbfac098f0a46d7711");
    test_str("\xBD", "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b");
    test_str("\xC9\x8C\x8E\x55", "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504");
    
    test_bytes(0x00, 55, "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7");
    test_bytes(0x00, 56, "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb");
    test_bytes(0x00, 57, "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785");
    test_bytes(0x00, 64, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    test_bytes(0x00, 1000, "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53");
    test_bytes(0x41, 1000, "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4");
    test_bytes(0x55, 1005, "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0");
    test_bytes(0x00, 1000000, "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025");
    test_bytes(0x61, 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    test_bytes(0x5A, 536870912, "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd");
    test_bytes(0x00, 1090519040, "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53");
    test_bytes(0x42, 1610612798, "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea");
    
    printf("All tests passed! Fine then ;)\n");
    
    return 0;
}
