#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture_single.h"
#include "swaf_pcre_cache_table.h"
#include "tx_store.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * SwafCapturePcreSingle
 * - 주어진 룰 ID에 해당하는 정규식을 캐시에서 조회한 뒤,
 * - 입력된 subject 문자열과 매칭 시도 후,
 * - 캡처된 그룹을 TxStore 구조체에 저장
 *
 * @param rule_id 룰 ID
 * @param subject 입력 문자열
 * @param tx 캡처 결과를 저장할 TxStore 구조체
 * @param is_hs_cache Hyperscan 캐시 사용 여부 (1: HS 캐시, 0: PCRE-only 캐시)
 * @return 1 캡처 성공, 0 캡처 실패
 */
int SwafCapturePcreSingle(const char *rule_id, const char *subject, TxStore *tx, int is_hs_cache) {
    if (!rule_id || !subject || !tx) {
        fprintf(stderr, "[PCRE] 유효하지 않은 입력\n");
        return 0;
    }

    /** 캐시 테이블 선택 (HS-only 또는 PCRE-only) */
    PcreCacheTable *cache_table = is_hs_cache ? HsCacheTableGetGlobal() : PcreOnlyCacheTableGetGlobal();

    /** 룰 ID 조회 */
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(cache_table, rule_id, strlen(rule_id));
    if (!entry || !entry->re) {
        fprintf(stderr, "[PCRE] 캡처 실패: 룰 %s 없음 (is_hs_cache=%d)\n", rule_id, is_hs_cache);
        
        /** 캐시 덤프 (디버그 용도) */
        PcreCacheTableDump(cache_table);
        return 0;
    }

    /** 매칭 데이터 생성 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(entry->re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패: 룰 ID = %s\n", rule_id);
        return 0;
    }

    /** 정규식 매칭 수행 */
    int rc = pcre2_match(entry->re, (PCRE2_SPTR)subject, strlen(subject), 0, 0, match_data, NULL);
    if (rc <= 0) {
        pcre2_match_data_free(match_data);
        return 0;
    }

    /** 매칭 데이터에서 캡처 그룹 추출 */
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    int group_count = pcre2_get_ovector_count(match_data);

    /** 전체 매칭 (TX.0) */
    if (tx->tx[0]) {
        free(tx->tx[0]);
        tx->tx[0] = NULL;
    }

    /** 전체 페이로드 저장 */
    size_t subject_len = strlen(subject);
    tx->tx[0] = (char *)malloc(subject_len + 1);
    if (tx->tx[0]) {
        strncpy(tx->tx[0], subject, subject_len);
        tx->tx[0][subject_len] = '\0';
        printf("[DEBUG] 룰 %s - TX.0 = %s\n", rule_id, tx->tx[0]);
    }

    /** 개별 그룹 (Group 1~N) */
    for (int i = 1; i < group_count && i < MAX_CAPTURE_GROUPS; ++i) {
        PCRE2_SIZE start = ovector[2 * i];
        PCRE2_SIZE end = ovector[2 * i + 1];
        size_t len = end - start;

        /** 기존 저장값이 있으면 해제 */
        if (tx->tx[i]) {
            free(tx->tx[i]);
            tx->tx[i] = NULL;
        }

        /** 실제로 매칭된 그룹만 저장 */
        if (len > 0) {
            tx->tx[i] = (char *)malloc(len + 1);
            if (!tx->tx[i]) {
                fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패 (TX.%d, 룰 %s)\n", i, rule_id);
                continue;
            }

            strncpy(tx->tx[i], subject + start, len);
            tx->tx[i][len] = '\0';
            printf("[DEBUG] 룰 %s - TX.%d = %s (len=%zu)\n", rule_id, i, tx->tx[i], len);
        } else {
            printf("[DEBUG] 룰 %s - TX.%d 그룹은 비어있음\n", rule_id, i);
        }
    }

    /** 매칭 데이터 해제 */
    pcre2_match_data_free(match_data);
    return 1;
}
