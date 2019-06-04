#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

int getentropy(void *buf, size_t len)
{
    errno= ENOSYS;
    return -1;
}
