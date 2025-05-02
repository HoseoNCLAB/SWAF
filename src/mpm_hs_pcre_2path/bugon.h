/* SWAF_BUG_ON 메시지 출력 헤더 */

#ifndef SWAF_BUGON_H
#define SWAF_BUGON_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef WAF_DEBUG
    #define SWAF_BUG_ON(x) do { \
        if ((x)) { \
            fprintf(stderr, "[SWAF_BUG_ON] %s:%d (%s): '%s'\n", __FILE__, __LINE__, __func__, #x); \
            abort(); \
        } \
    } while(0)
#else
    #define SWAF_BUG_ON(x) ((void)0)
#endif

#endif /* SWAF_BUGON_H */