#ifndef SWAF_HOTRELOAD_H
#define SWAF_HOTRELOAD_H

void SwafUnloadRules(void);
int SwafReloadRules(const char *hs_path, const char *pcre_path);

#endif // SWAF_HOTRELOAD_H

