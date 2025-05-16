#ifndef __SWAF_PCRE_CAPTURE_H__
#define __SWAF_PCRE_CAPTURE_H__

#include "tx_store.h"

int SwafCapturePcreSingle(const char *rule_id, const char *subject, TxStore *tx, int is_hs_cache);

#endif /* __SWAF_PCRE_CAPTURE_H__ */
