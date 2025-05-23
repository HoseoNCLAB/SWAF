#ifndef SWAF_PCRE_CAPTURE_CHAIN_H
#define SWAF_PCRE_CAPTURE_CHAIN_H

#include <pcre2.h>
#include "tx_store.h"

int SwafCapturePcreChain(const char *chain_base_id, const char *subject, \
                         TxStore *tx, pcre2_match_data *match_data);

#endif /* SWAF_PCRE_CAPTURE_CHAIN_H */

