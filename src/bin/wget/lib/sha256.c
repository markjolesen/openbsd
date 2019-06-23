#include <stdlib.h>
#include <stddef.h>
#include <openssl/sha.h>

void*
sha256_buffer(const char *buf, size_t len, void* resblock)
{
    return SHA256(buf, len, resblock);

}

