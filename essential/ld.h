#ifndef _LD_

#if INTPTR_MAX == INT32_MAX
    #define THIS_IS_32_BIT_ENVIRONMENT
		#define _LD_ "%lld"
		#define _LX_ "0x%08llx"
#elif INTPTR_MAX == INT64_MAX
    #define THIS_IS_64_BIT_ENVIRONMENT
		#define _LD_ "%ld"
		#define _LX_ "0x%08lx"
#else
    #error "Environment not 32 or 64-bit."
#endif

#endif /* ifndef _LD_ */
