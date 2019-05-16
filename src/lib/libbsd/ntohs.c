/*	$OpenBSD: ntohs.c,v 1.9 2014/07/21 01:51:10 guenther Exp $ */
/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <stdint.h>

#define LITTLE_ENDIAN 1234
#define BYTE_ORDER LITTLE_ENDIAN

uint16_t
ntohs(uint16_t x)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t *s = (uint8_t *) &x;
	return (uint16_t)(s[0] << 8 | s[1]);
#else
	return x;
#endif
}
