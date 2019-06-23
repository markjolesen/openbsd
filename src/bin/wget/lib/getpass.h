/* Obsolete; consider using unistd.h instead.  */

/* Get getpass declaration, if available.  */
#include <unistd.h>

#if defined(__WATCOMC__)
char * getpass (const char *prompt);
#endif
