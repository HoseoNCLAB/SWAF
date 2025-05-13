#ifndef SWAF_PCRE_LOADER_H
#define SWAF_PCRE_LOADER_H

#include <pcre2.h>

/* HS-only 룰 초기화 */
int SwafInitHsOnly(const char *json_path);

/* PCRE-only 룰 초기화 */
int SwafInitPcreOnly(const char *json_path);

#endif /* SWAF_PCRE_LOADER_H */
