/*
* License CC0 PUBLIC DOMAIN
*
* To the extent possible under law, Mark J. Olesen has waived all copyright 
* and related or neighboring rights to libbsd.h file. This work is published 
* from: United States.
*
*/
#if !defined(__libbsd_h__)

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LITTLE_ENDIAN 1234
#define BYTE_ORDER LITTLE_ENDIAN

uint32_t arc4random(void);
void arc4random_buf(void *buf, size_t n);
int asprintf(char **str, const char *fmt, ...);
int vasprintf(char **str, const char *fmt, va_list ap);
void explicit_bzero(void *buf, size_t len);
void freezero(void *ptr, size_t sz);
time_t timegm(struct tm *tmp);
int posix_memalign(void **memptr, size_t alignment, size_t size);
void* reallocarray(void *optr, size_t nmemb, size_t size);
void* recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size);
int timingsafe_bcmp(const void *b1, const void *b2, size_t n);
int timingsafe_memcmp(const void *b1, const void *b2, size_t len);
size_t strnlen(const char* s, size_t maxlen);
char* strndup(const char *str, size_t maxlen);
char * strsep(char **stringp, const char *delim);
int ftruncate(int fd, off_t len);
ssize_t pread(int d, void *buf, size_t nbytes, off_t offset);
ssize_t pwrite(int d, const void *buf, size_t nbytes, off_t offset);
int getentropy(void *buf, size_t len);
const char* getprogname();
struct tm* gmtime_r(const time_t *clock, struct tm* result);

uint32_t htonl(uint32_t x);
uint16_t htons(uint16_t x);
uint16_t ntohs(uint16_t x);

#ifdef __cplusplus
}
#endif

#define __libbsd_h__
#endif
