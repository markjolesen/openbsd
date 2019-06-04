#include <stddef.h>
#include <stdlib.h>
#include <time.h>

struct tm* gmtime_r(const time_t *clock, struct tm* result)
{
	struct tm* ptr;

	ptr= gmtime(clock);

	if (ptr)
	{
		memcpy(result, ptr, sizeof(*ptr));
		return result;
	}

	return 0;
}
