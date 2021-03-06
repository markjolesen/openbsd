/*	$OpenBSD: htonl.c,v 1.7 2014/07/21 01:51:10 guenther Exp $ */
/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <stdint.h>

#define LITTLE_ENDIAN 1234
#define BYTE_ORDER LITTLE_ENDIAN

uint32_t
htonl(uint32_t x)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t *s = (uint8_t *)&x;
	return (uint32_t)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
#else
	return x;
#endif
}
