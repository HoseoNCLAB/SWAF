#ifndef SWAF_PCRE_CAPTURE_CHAIN_H
#define SWAF_PCRE_CAPTURE_CHAIN_H

#include "tx_store.h"

void ResetMatchedChainHistory();
int AddMatchedChainHistory(const char *chain_base_id);
int IsChainAlreadyMatched(const char *chain_base_id);
int SwafCapturePcreChain(const char *chain_base_id, const char *payload, TxStore *tx);

#endif /* SWAF_PCRE_CAPTURE_CHAIN_H */

