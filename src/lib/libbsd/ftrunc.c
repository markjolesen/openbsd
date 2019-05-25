/*
 * Public domain
 *
 * Kinichiro Inoguchi <inoguchi@openbsd.org>
 */

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>

int ftruncate(int fd, off_t len)
{
	return chsize(fd, len);
}
