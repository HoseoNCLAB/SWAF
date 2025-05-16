#ifndef SWAF_PCRE_LOADER_H
#define SWAF_PCRE_LOADER_H

#include <pcre2.h>

int SwafInitHsOnly(const char *json_path);
int SwafInitPcreOnly(const char *json_path);

#endif /* SWAF_PCRE_LOADER_H */
