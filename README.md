
# sha256
SHA-256 algorithm implementation (С/С++)

- Pure C with no platform or architecture dependencies
- Easy to use - just include sha256.h and add sha256.c to your project source files
- Can be used in C++, extends API appropriately
- Two types of API: easy - for hashing strings, etc in a single call; extended - for hashing files, streams, etc
- Based on the pseudocode algorithm from [Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Pseudocode)
- Pretty fast, comparable to sha256sum in speed
# Usage
## Easy API - String hashing example
```c
const char* str = "test";
char hash[65] = {0}; // Notice the additional null-byte
sha256_easy_hash_hex(str, strlen(str), hash);
printf("%s\n", hash);
```
## Extended API - File hashing example
```c
FILE* file = fopen("test", "rb");
char buffer[1024];
size_t size;
struct sha256_buff buff;
sha256_init(&buff);
while (!feof(file)) {
    // Hash file by 1kb chunks, instead of loading into RAM at once
    size = fread(buffer, 1, 1024, file);
    sha256_update(&buff, buffer, size);
}
char hash[65] = {0};
sha256_finalize(&buff);
sha256_read_hex(&buff, hash);
printf("%s\n", hash);
```
## C++
```cpp
std::cout << SHA256::hashString("test") << std::endl;

SHA256 buff;
buff.update("test", 4);
std::cout << buff.hash() << std::endl;
```
