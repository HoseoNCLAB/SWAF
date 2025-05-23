#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_cache_table.h"
#include "tx_store.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * SwafCapturePcreChain
 * - 체인 룰 캡처 함수 (체인 캐시)
 * - 체인 베이스 ID와 페이로드를 받아 캡처 수행
 *
 * @param chain_base_id: 체인 베이스 ID
 * @param subject: 매칭할 페이로드
 * @param tx: TX 스토어
 * @return: 1 (캡처 성공), 0 (캡처 실패)
 * @note: 이 함수는 체인 룰 캐시에서 체인 베이스 ID를 검색하여 캡처 수행
 */
int SwafCapturePcreChain(const char *chain_base_id, const char *subject, \
                         TxStore *tx, pcre2_match_data *match_data) {
    if (!chain_base_id || !subject || !tx || !match_data) {
        fprintf(stderr, "[PCRE] 캡처 입력 오류\n");
        return 0;
    }

    FreeTxStore(tx);

    PcreCacheEntry *base_entry = (PcreCacheEntry *)PcreCacheTableLookup(
        ChainCacheTableGetGlobal(), chain_base_id, strlen(chain_base_id));
    if (!base_entry || !base_entry->next) {
        fprintf(stderr, "[PCRE] 체인 베이스 '%s' 없음\n", chain_base_id);
        return 0;
    }

    int tx_index = 0;
    PcreCacheEntry *current_step = base_entry->next;
    while (current_step) {
        /** 나중에 pcre 매치 제거 */
        int rc = pcre2_match(current_step->re, (PCRE2_SPTR)subject, strlen(subject), 0, 0, match_data, NULL);
        if (rc <= 0) return 0;

        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        int group_count = pcre2_get_ovector_count(match_data);

        for (int i = 0; i < group_count && tx_index < MAX_CAPTURE_GROUPS; ++i, ++tx_index) {
            PCRE2_SIZE start = ovector[2 * i];
            PCRE2_SIZE end = ovector[2 * i + 1];
            size_t len = end - start;

            if (len > 0) {
                tx->tx[tx_index] = (char *)malloc(len + 1);
                strncpy(tx->tx[tx_index], subject + start, len);
                tx->tx[tx_index][len] = '\0';
            }
        }

        current_step = current_step->next;
    }

    PrintTx(chain_base_id, tx);
    return 1;
}
