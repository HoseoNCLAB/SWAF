#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_cache_table.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAIN_DEPTH 10  /* 체인 룰 최대 단계 수 */

/**
 * SwafCapturePcreChain
 * - 주어진 체인 룰 ID에 대해 "룰ID_0", "룰ID_1", ... 순서대로 PCRE 매칭을 수행하고,
 * - 각 단계에서의 캡처 그룹을 TxStore에 저장
 *
 * @param chain_base_id 체인 룰 기본 ID (예: "942130")
 * @param subject 입력 문자열
 * @param tx 캡처 결과를 저장할 TxStore 구조체
 * @return 1 모든 체인 매칭 및 캡처 성공, 0 실패
 */
int SwafCapturePcreChain(const char *chain_base_id, const char *subject, TxStore *tx) {
    if (!chain_base_id || !subject || !tx)
        return 0;

    char chain_id[64];

    for (int i = 0; i < MAX_CHAIN_DEPTH; i++) {
        snprintf(chain_id, sizeof(chain_id), "%s_%d", chain_base_id, i);

        pcre2_code *re = PcreCacheTableGet(chain_id);
        if (!re) {
            /* 다음 체인 룰이 없으면 종료 */
            break;
        }

        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
        if (!match_data) {
            fprintf(stderr, "[PCRE] match_data 생성 실패 (%s)\n", chain_id);
            return 0;
        }

        int rc = pcre2_match(
            re, (PCRE2_SPTR)subject, strlen(subject), 0, 0, match_data, NULL);

        if (rc <= 0) {
            pcre2_match_data_free(match_data);
            return 0;
        }

        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

        for (int j = 0; j < rc && j < MAX_CAPTURE_GROUPS; ++j) {
            PCRE2_SIZE start = ovector[2 * j];
            PCRE2_SIZE end = ovector[2 * j + 1];
            size_t len = end - start;

            if (len >= MAX_CAPTURE_LEN)
                len = MAX_CAPTURE_LEN - 1;

            if (tx->tx[j]) free(tx->tx[j]);
            tx->tx[j] = (char *)malloc(len + 1);
            if (!tx->tx[j]) {
                fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패 (%s TX.%d)\n", chain_id, j);
                continue;
            }

            strncpy(tx->tx[j], subject + start, len);
            tx->tx[j][len] = '\0';
        }

        pcre2_match_data_free(match_data);
    }

    return 1;
}

