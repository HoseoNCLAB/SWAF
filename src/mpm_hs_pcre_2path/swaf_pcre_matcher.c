#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_matcher.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_capture_single.h"

#include <pcre2.h>
#include <string.h>
#include <stdio.h>


/**
 * MatchPcreSingle
 * - 단일 룰 매칭
 * - 룰 ID와 페이로드를 받아 매칭 수행
 *
 * @param entry: 단일 룰 캐시 엔트리
 * @param payload: 매칭할 페이로드
 * @return: 1 (매칭 성공), 0 (매칭 실패)
 * @note: 이 함수는 단일 룰을 매칭
 */
static int MatchPcreSingle(PcreCacheEntry *entry, const char *payload, pcre2_match_data **out_match_data) {
    if (!entry || !entry->re) {
        fprintf(stderr, "[PCRE] 단일 룰이 NULL이거나 정규식이 없습니다 (룰 ID: %s)\n", \
                entry ? entry->rule_id : "알 수 없음");
        return 0;
    }

    if (entry->next != NULL) {
        fprintf(stderr, "[PCRE] 단일 룰이 아닌 체인 엔트리를 단일 룰로 처리하려고 했습니다 (룰 ID: %s)\n", \
                entry->rule_id);
        return 0;
    }

    *out_match_data = pcre2_match_data_create_from_pattern(entry->re, NULL);
    if (!*out_match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패 (룰 ID: %s)\n", entry->rule_id);
        return 0;
    }

    int rc = pcre2_match(entry->re, (PCRE2_SPTR)payload, strlen(payload), 0, 0, *out_match_data, NULL);

    int is_negated = entry->is_negated;
    int is_malicious = (!is_negated && rc > 0) || (is_negated && rc <= 0);

    if (is_malicious) {
        if (is_negated)
            printf("[ALERT] 단일 룰 부정 매칭 실패 (악성): %s (negated=1)\n", entry->rule_id);
        else
            printf("[ALERT] 단일 룰 매칭 성공 (악성): %s (negated=0)\n", entry->rule_id);
    } else {
        if (is_negated)
            printf("[DEBUG] 단일 룰 부정 매칭 성공 (정상): %s (negated=1)\n", entry->rule_id);
        else
            printf("[DEBUG] 단일 룰 매칭 실패 (정상): %s (negated=0)\n", entry->rule_id);
    }

    return is_malicious;
}


/**
 * MatchPcreChain
 * - 체인 룰 매칭
 * - 체인 베이스 ID와 페이로드를 받아 매칭 수행
 *
 * @param chain_entry: 체인 룰 캐시 엔트리
 * @param payload: 매칭할 페이로드
 * @return: 1 (매칭 성공), 0 (매칭 실패)
 * @note: 이 함수는 체인 룰을 매칭
 */
static int MatchPcreChain(PcreCacheEntry *chain_entry, const char *payload, \
                            pcre2_match_data *match_data) {
    if (!chain_entry || !chain_entry->next) {
        fprintf(stderr, "[PCRE] 체인 엔트리가 NULL이거나 첫 단계 없음 (체인 베이스: %s)\n",
                chain_entry ? chain_entry->rule_id : "알 수 없음");
        return 0;
    }

    PcreCacheEntry *current_step = chain_entry->next;
    while (current_step) {
        if (!current_step->re) {
            fprintf(stderr, "[PCRE] 정규식 없음 (단계: %s)\n", current_step->rule_id);
            return 0;
        }

        int rc = pcre2_match(current_step->re, (PCRE2_SPTR)payload, strlen(payload), \
                            0, 0, match_data, NULL);
        int is_negated = current_step->is_negated;
        int match_fail = is_negated ? (rc > 0) : (rc <= 0);

        if (match_fail) {
            printf("[DEBUG] 체인 단계 매칭 실패: %s (단계: %s, negated=%d)\n", \
                   chain_entry->rule_id, current_step->rule_id, is_negated);
            return 0;
        }

        current_step = current_step->next;
    }

    return 1;
}


/**
 * SwafMatchPcreSingle
 * - 단일 룰 매칭 함수 (단일 캐시)
 * - 룰 ID와 페이로드를 받아 매칭 수행
 * - 매칭 성공 시 TX 캡처 수행
 *
 * @param rule_id: 룰 ID
 * @param payload: 매칭할 페이로드
 * @param tx: TX 스토어
 * @return: 1 (매칭 성공), 0 (매칭 실패)
 * @note: 이 함수는 단일 룰 캐시에서 룰 ID를 검색하여 매칭 수행
 */
int SwafMatchPcreSingle(const char *rule_id, const char *payload, TxStore *tx) {
    if (!rule_id || !payload || !tx) {
        fprintf(stderr, "[PCRE] 입력이 NULL입니다 (룰 ID = %s)\n", rule_id ? rule_id : "알 수 없음");
        return 0;
    }

    /** 단일 룰 캐시에서만 검색 */
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(PcreOnlyCacheTableGetGlobal(), \
                                                                    rule_id, \
                                                                    strlen(rule_id));
    if (!entry || entry->next != NULL) {
        fprintf(stderr, "[PCRE] 단일 룰 '%s' 없음 또는 체인 룰로 잘못 처리됨 (PCRE 캐시)\n", rule_id);
        return 0;
    }

    /** 1. 매칭 여부 판단 + 로그 출력 */
    pcre2_match_data *match_data = NULL;
    int is_malicious = MatchPcreSingle(entry, payload, &match_data);

    /** 2. 악성일 경우만 TX 저장 및 출력 */
    if (is_malicious) {
        SwafCapturePcreSingle(rule_id, payload, tx, match_data, 0);
    }

    if (match_data) {
        pcre2_match_data_free(match_data);
    }

    return is_malicious;
}


/**
 * SwafMatchPcreChain
 * - 체인 룰 매칭 함수 (체인 캐시)
 * - 체인 베이스 ID와 페이로드를 받아 매칭 수행
 * - 매칭 성공 시 TX 캡처 수행
 *
 * @param chain_base_id: 체인 베이스 ID
 * @param payload: 매칭할 페이로드
 * @param tx: TX 스토어
 * @return: 1 (매칭 성공), 0 (매칭 실패)
 * @note: 이 함수는 체인 룰 캐시에서 체인 베이스 ID를 검색하여 매칭 수행
 * @note: 체인 베이스 ID가 NULL인 경우 오류 메시지 출력
 */
int SwafMatchPcreChain(const char *chain_base_id, const char *payload, TxStore *tx) {
    if (!chain_base_id || !payload || !tx) {
        fprintf(stderr, "[PCRE] 입력이 NULL입니다 (체인 ID: %s)\n",
                chain_base_id ? chain_base_id : "알 수 없음");
        return 0;
    }

    PcreCacheEntry *chain_entry = (PcreCacheEntry *)PcreCacheTableLookup(
        ChainCacheTableGetGlobal(), chain_base_id, strlen(chain_base_id));
    if (!chain_entry || !chain_entry->next) {
        fprintf(stderr, "[PCRE] 체인 베이스 '%s' 없음 또는 첫 단계 없음\n", chain_base_id);
        return 0;
    }

    /** 공용 match_data 생성 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(chain_entry->next->re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패\n");
        return 0;
    }

    int is_malicious = MatchPcreChain(chain_entry, payload, match_data);

    if (is_malicious) {
        if (!SwafCapturePcreChain(chain_base_id, payload, tx, match_data)) {
            fprintf(stderr, "[PCRE] 캡처 실패\n");
            is_malicious = 0;
        } else {
            printf("[ALERT] 체인 룰 '%s' 매칭 성공 (모든 단계 통과)\n", chain_base_id);
        }
    }

    pcre2_match_data_free(match_data);
    return is_malicious;
}


/**
 * SwafPcreMatchWithId
 * - Hyperscan 매칭된 룰 ID에 대해 PCRE 매칭 수행
 * - TX 캡처를 포함하여 처리
 *
 * @param subject: 매칭할 문자열
 * @param len: 문자열 길이
 * @param rule_id: 룰 ID
 * @param tx: TX 스토어
 * @return: 1 (매칭 성공), 0 (매칭 실패)
 * @note: 룰 ID는 문자열로 변환하여 캐시에서 검색
 */
int SwafPcreMatchWithId(const char *subject, int len, uint32_t rule_id, TxStore *tx) {
    /** 룰 ID 문자열로 변환 */
    char rule_id_str[16];
    snprintf(rule_id_str, sizeof(rule_id_str), "%u", rule_id);

    /** Hyperscan 캐시 테이블에서 룰 ID 조회 */
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(HsCacheTableGetGlobal(), \
                                                                    rule_id_str, \
                                                                    strlen(rule_id_str));
    if (!entry || !entry->re) {
        fprintf(stderr, "[PCRE] capture fail: 룰 %s 없음 (Hyperscan 캐시)\n", rule_id_str);
        return 0;
    }

    /** match_data 생성 및 매칭 수행 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(entry->re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패 (룰 ID: %s)\n", rule_id_str);
        return 0;
    }

    int rc = pcre2_match(entry->re, (PCRE2_SPTR)subject, len, 0, 0, match_data, NULL);

    int is_negated = entry->is_negated;
    int is_malicious = (!is_negated && rc > 0) || (is_negated && rc <= 0);

    int capture_success = 0;
    if (is_malicious) {
        printf("[DEBUG] SwafCapturePcreSingle 시작 - 룰 ID: %s\n", rule_id_str);
        capture_success = SwafCapturePcreSingle(rule_id_str, subject, tx, match_data, 1);
    }

    pcre2_match_data_free(match_data);
    return capture_success;
}
