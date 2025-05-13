#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_matcher.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_capture_single.h"

#include <pcre2.h>
#include <string.h>
#include <stdio.h>

#define MAX_CHAIN_DEPTH 10  /* 체인 룰 최대 단계 수 */

/**
 * 공통 룰 매칭 함수
 * - 주어진 룰 ID에 대해 PCRE 매칭 수행
 * - 캐시에서 룰을 조회하고 부정 매칭(!@rx) 여부를 반영하여 결과 반환
 * 
 * @param rule_id 룰 ID
 * @param payload 입력 문자열
 * @param hs_cache HS-only 캐시 사용 여부
 * @return 1 (매칭), 0 (비매칭)
 */
static int MatchPcreWithCache(const char *rule_id, const char *payload, int hs_cache) {
    PcreCacheTable *table = hs_cache ? HsCacheTableGetGlobal() : PcreOnlyCacheTableGetGlobal();

    pcre2_code *re = (pcre2_code *)PcreCacheTableLookup(table, rule_id, strlen(rule_id));
    if (!re) {
        fprintf(stderr, "[PCRE] 룰 ID '%s'에 해당하는 정규식 없음 (%s 캐시)\n", rule_id, hs_cache ? "HS" : "PCRE");
        PcreCacheTableDump(table);
        return 0;
    }

    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패: 룰 ID = %s\n", rule_id);
        return 0;
    }

    int rc = pcre2_match(re, (PCRE2_SPTR)payload, strlen(payload), 0, 0, match_data, NULL);
    pcre2_match_data_free(match_data);

    int is_negated = PcreCacheTableIsNegated(rule_id);
    return is_negated ? (rc <= 0) : (rc > 0);
}

/**
 * SwafMatchPcre
 * - 주어진 룰 ID에 해당하는 정규식을 캐시 테이블에서 조회 후 매칭 시도
 * - HS-only 룰과 PCRE-only 룰을 구분하여 처리
 * - 부정 매칭 (!@rx) 여부를 반영하여 결과 반환
 *  
 * @param rule_id 룰 ID
 * @param payload 입력 문자열
 * @return 1 매칭 성공, 0 매칭 실패
 */
int SwafMatchPcre(const char *rule_id, const char *payload) {
    /* 룰 ID 출력 (디버그용) */
    printf("[DEBUG] 룰 ID 조회 시도: '%s' (len=%zu)\n", rule_id, strlen(rule_id));

    /* 룰 ID에 해당하는 컴파일된 정규식 객체를 캐시에서 가져옴 */
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(PcreOnlyCacheTableGetGlobal(), rule_id, strlen(rule_id));
    if (!entry) {
        fprintf(stderr, "[ERROR] 룰 ID '%s'에 해당하는 엔트리를 찾을 수 없음\n", rule_id);
        return 0;
    }

    if (!entry->re) {
        fprintf(stderr, "[ERROR] 룰 ID '%s'의 정규식 객체가 NULL입니다\n", rule_id);
        return 0;
    }

    /* 정규식 매칭을 위한 match_data 구조체 생성 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(entry->re, NULL);
    if (!match_data) {
        fprintf(stderr, "[ERROR] 룰 ID '%s'의 match_data 생성 실패\n", rule_id);
        return 0;
    }

    /* 실제 매칭 수행 */
    int rc = pcre2_match(entry->re, (PCRE2_SPTR)payload, strlen(payload), 0, 0, match_data, NULL);

    /* match_data 구조체 해제 */
    pcre2_match_data_free(match_data);

    /* 해당 룰이 부정 매칭인지 여부 확인 */
    int is_negated = entry->is_negated;

    /* 결과 해석 */
    int matched = is_negated ? (rc <= 0) : (rc > 0);
    printf("[DEBUG] 룰 ID '%s' 매칭 결과: %s\n", rule_id, matched ? "성공" : "실패");
    
    return matched;
}

/**
 * 체인 룰 매칭
 * - PCRE-only 캐시에서만 처리
 */
int SwafMatchPcreChain(const char *chain_base_id, const char *payload) {
    char chain_id[64];

    for (int i = 0; i < MAX_CHAIN_DEPTH; i++) {
        snprintf(chain_id, sizeof(chain_id), "%s_%d", chain_base_id, i);

        if (!MatchPcreWithCache(chain_id, payload, 0)) {
            return 0;  // 체인 단계 중 하나라도 실패하면 전체 실패
        }
    }

    return 1;  // 모든 체인 매칭 통과
}

/**
 * SwafPcreMatchWithId
 * - 주어진 rule_id에 대해 PCRE 매칭 수행
 * - Hyperscan 매칭된 룰은 HsCacheTable에서만 처리
 * 
 * @param subject 입력 문자열
 * @param len 입력 문자열 길이
 * @param rule_id 룰 ID
 * @param tx 캡처 결과 저장용 TxStore 구조체
 * @return 1 (캡처 성공), 0 (캡처 실패)
 */
int SwafPcreMatchWithId(const char *subject, int len, uint32_t rule_id, TxStore *tx) {
    char rule_id_str[16];
    snprintf(rule_id_str, sizeof(rule_id_str), "%u", rule_id);

    // Hyperscan에서 매칭된 룰은 HsCacheTable에서만 검색
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(HsCacheTableGetGlobal(), rule_id_str, strlen(rule_id_str));
    if (!entry || !entry->re) {
        fprintf(stderr, "[PCRE] capture fail: 룰 %s 없음\n", rule_id_str);
        return 0;
    }

    // 단일 룰 캡처 처리
    printf("[DEBUG] SwafCapturePcreSingle 시작 - 룰 ID: %s\n", rule_id_str);
    if (SwafCapturePcreSingle(rule_id_str, subject, tx, 1)) {
        return 1;
    }

    return 0;
}
