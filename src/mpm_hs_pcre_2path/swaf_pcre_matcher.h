#ifndef __SWAF_PCRE_MATCHER_H__
#define __SWAF_PCRE_MATCHER_H__

#include <stdint.h>
#include "tx_store.h"


int SwafMatchPcreSingle(const char *rule_id, const char *subject, TxStore *tx);
int SwafMatchPcreChain(const char *chain_id, const char *payload, TxStore *tx);
int SwafPcreMatchWithId(const char *subject, int len, uint32_t rule_id, TxStore *tx);

#endif /* __SWAF_PCRE_MATCHER_H__ */