#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  *memptr= malloc(size);
  return 1;
}
