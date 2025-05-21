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
int SwafCapturePcreChain(const char *chain_base_id, const char *subject, TxStore *tx) {
    if (!chain_base_id || !subject || !tx) {
        fprintf(stderr, "[PCRE] 유효하지 않은 입력 (체인 베이스 ID 또는 subject 또는 tx가 NULL)\n");
        return 0;
    }

    /** 기존 캡처 데이터 초기화 */
    FreeTxStore(tx);

    /** 체인 베이스 엔트리 검색 */
    PcreCacheEntry *base_entry = (PcreCacheEntry *)PcreCacheTableLookup(ChainCacheTableGetGlobal(), \
                                                                        chain_base_id, \
                                                                        strlen(chain_base_id));
    if (!base_entry || !base_entry->next) {
        fprintf(stderr, "[PCRE] 체인 베이스 '%s' 없음 또는 첫 단계 없음 (체인 캐시)\n", chain_base_id);
        return 0;
    }

    /** 체인의 각 단계 순회 */
    int tx_index = 0;
    PcreCacheEntry *current_step = base_entry->next;
    while (current_step) {
        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(current_step->re, NULL);
        if (!match_data) {
            fprintf(stderr, "[PCRE] match_data 생성 실패 (체인 베이스='%s')\n", chain_base_id);
            return 0;
        }

        /** 정규식 매칭 시도 */
        int rc = pcre2_match(current_step->re, (PCRE2_SPTR)subject, strlen(subject), \
                                0, 0, match_data, NULL);

        if (rc <= 0) {
            printf("[DEBUG] 체인 단계 매칭 실패 (체인 베이스='%s', 단계='%s')\n", chain_base_id, \
                    current_step->rule_id);
            pcre2_match_data_free(match_data);
            return 0;
        }

        /** TX 그룹 캡처 (0부터 시작) */
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        int group_count = pcre2_get_ovector_count(match_data);

        for (int i = 0; i < group_count && tx_index < MAX_CAPTURE_GROUPS; ++i, ++tx_index) {
            int start = (int)ovector[2 * i];
            int end = (int)ovector[2 * i + 1];
            int length = end - start;

            if (length > 0) {
                char *capture = (char *)malloc(length + 1);
                if (!capture) {
                    fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패\n");
                    pcre2_match_data_free(match_data);
                    return 0;
                }
                strncpy(capture, subject + start, length);
                capture[length] = '\0';
                tx->tx[tx_index] = capture;
            }
        }

        pcre2_match_data_free(match_data);
        current_step = current_step->next;
    }

    PrintTx(chain_base_id, tx);

    /** 모든 단계 매칭 성공 시 TX 캡처 완료 */
    return 1;
}
