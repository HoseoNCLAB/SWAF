#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture_single.h"
#include "swaf_pcre_cache_table.h"
#include "tx_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * SwafCapturePcreSingle
 * - 단일 룰 캡처 함수 (단일 캐시)
 * - 룰 ID와 페이로드를 받아 캡처 수행
 *
 * @param rule_id: 룰 ID
 * @param subject: 매칭할 페이로드
 * @param tx: TX 스토어
 * @param is_hs_cache: HS 캐시 여부 (1: HS 캐시, 0: PCRE 캐시)
 * @return: 1 (캡처 성공), 0 (캡처 실패)
 */
int SwafCapturePcreSingle(const char *rule_id, const char *subject, TxStore *tx, \
                            pcre2_match_data *match_data, int is_hs_cache) {
    if (!rule_id || !subject || !tx || !match_data) {
        fprintf(stderr, "[PCRE] 유효하지 않은 입력 또는 match_data NULL\n");
        return 0;
    }

    /** 캐시 테이블 선택 */
    PcreCacheTable *cache_table = is_hs_cache ? HsCacheTableGetGlobal() : PcreOnlyCacheTableGetGlobal();

    /** 룰 ID 조회 */
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(cache_table, rule_id, strlen(rule_id));
    if (!entry || !entry->re) {
        fprintf(stderr, "[PCRE] 캡처 실패: 룰 %s 없음 (is_hs_cache=%d)\n", rule_id, is_hs_cache);
        return 0;
    }

    /** 기존 캡처 데이터 정리 */
    for (int i = 0; i < MAX_CAPTURE_GROUPS; ++i) {
        if (tx->tx[i]) {
            free(tx->tx[i]);
            tx->tx[i] = NULL;
        }
    }

    /** 매칭된 그룹 정보 추출 */
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    int group_count = pcre2_get_ovector_count(match_data);

    /** TX.0: 정규식 전체 매칭 영역 저장 */
    PCRE2_SIZE start = ovector[0];
    PCRE2_SIZE end = ovector[1];
    size_t len = end - start;
    tx->tx[0] = (char *)malloc(len + 1);
    if (tx->tx[0]) {
        strncpy(tx->tx[0], subject + start, len);
        tx->tx[0][len] = '\0';
    }

    /** TX.1 ~ TX.N: 캡처 그룹 저장 */
    for (int i = 1; i < group_count && i < MAX_CAPTURE_GROUPS; ++i) {
        PCRE2_SIZE cap_start = ovector[2 * i];
        PCRE2_SIZE cap_end = ovector[2 * i + 1];
        size_t cap_len = cap_end - cap_start;

        if (cap_len > 0) {
            tx->tx[i] = (char *)malloc(cap_len + 1);
            if (!tx->tx[i]) {
                fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패 (TX.%d, 룰 %s)\n", i, rule_id);
                continue;
            }
            strncpy(tx->tx[i], subject + cap_start, cap_len);
            tx->tx[i][cap_len] = '\0';
        }
    }

    PrintTx(rule_id, tx);
    return 1;
}
