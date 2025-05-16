#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_cache_table.h"
#include "tx_store.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAIN_DEPTH 10      /** 체인 룰 최대 단계 수 */
#define MAX_CHAIN_HISTORY 1024  /** 체인 룰 매칭 히스토리 최대 수 */

/** 체인 매칭 히스토리 */
static char matched_chain_ids[MAX_CHAIN_HISTORY][64];
static int matched_chain_count = 0;

/**
 * ResetMatchedChainHistory
 * - 체인 매칭 기록 초기화
 * - 매칭된 체인 ID 초기화
 * - 최대 히스토리 수를 초과하면 실패
 *
 * @note: 이 함수는 매칭된 체인 ID를 초기화하여 중복 매칭을 방지
 */
void ResetMatchedChainHistory() {
    matched_chain_count = 0;
    memset(matched_chain_ids, 0, sizeof(matched_chain_ids));
}

/**
 * AddMatchedChainHistory
 * - 체인 룰 매칭 기록 추가
 * - 매칭된 체인 ID를 히스토리에 추가
 * - 최대 히스토리 수를 초과하면 실패
 *
 * @param chain_base_id: 체인 베이스 ID
 * @return: 1 (성공), 0 (실패)
 * @note: 이 함수는 매칭된 체인 ID를 히스토리에 추가하여 중복 매칭을 방지
 * @note: 매칭된 체인 ID는 최대 MAX_CHAIN_HISTORY 수까지 저장 가능
 * @note: 매칭된 체인 ID는 문자열로 저장되며, 최대 64자까지 지원
 */
int AddMatchedChainHistory(const char *chain_base_id) {
    if (matched_chain_count >= MAX_CHAIN_HISTORY) {
        fprintf(stderr, "[PCRE] 체인 매칭 히스토리가 가득 찼습니다.\n");
        return 0;
    }
    strcpy(matched_chain_ids[matched_chain_count++], chain_base_id);
    return 1;
}

/**
 * FreeMatchedChainHistory
 * - 체인 룰이 이미 매칭된 경우인지 확인
 * - 매칭된 체인 ID가 히스토리에 존재하는지 확인
 * - 중복 매칭 방지
 *
 * @param chain_base_id: 체인 베이스 ID
 * @return: 1 (이미 매칭됨), 0 (매칭되지 않음)
 * @note: 이 함수는 매칭된 체인 ID가 히스토리에 존재하는지 확인하여 중복 매칭을 방지
 */
int IsChainAlreadyMatched(const char *chain_base_id) {
    for (int i = 0; i < matched_chain_count; ++i) {
        if (strcmp(matched_chain_ids[i], chain_base_id) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * SwafCapturePcreChain
 * - 체인 룰 캡처 함수
 * - 주어진 체인 베이스 ID에 대해 매칭된 모든 단계를 캡처
 *
 * @param chain_base_id: 체인 베이스 ID
 * @param subject: 매칭할 문자열
 * @param tx: TxStore 구조체 포인터
 * @return: 1 (성공), 0 (실패)
 * @note: 이 함수는 체인 룰을 매칭하고, 각 단계에서 캡처된 그룹을 TxStore에 저장
 * @note: 각 단계는 이전 단계의 캡처 결과를 기반으로 매칭됨
 * @note: 캡처된 그룹은 TxStore 구조체에 저장되며, 각 그룹은 0부터 시작하는 인덱스를 가짐
 * @note: 캡처된 그룹은 최대 MAX_CAPTURE_GROUPS 수까지 저장 가능
 * @note: 캡처된 그룹은 문자열로 저장되며, 최대 1024자까지 지원
 */
int SwafCapturePcreChain(const char *chain_base_id, const char *subject, TxStore *tx) {
    if (!chain_base_id || !subject || !tx) {
        fprintf(stderr, "[PCRE] 유효하지 않은 입력 (체인 베이스 ID 또는 subject 또는 tx가 NULL)\n");
        return 0;
    }

    /** 기존 캡처 데이터 초기화 */
    FreeTxStore(tx);

    /** 체인 베이스 엔트리 검색 */
    PcreCacheEntry *base_entry = (PcreCacheEntry *)PcreCacheTableLookup(ChainCacheTableGetGlobal(), chain_base_id, strlen(chain_base_id));
    if (!base_entry || !base_entry->next) {
        fprintf(stderr, "[PCRE] 체인 베이스 '%s' 없음 또는 첫 단계 없음 (체인 캐시)\n", chain_base_id);
        return 0;
    }

    /** 체인의 각 단계 순회 */
    PcreCacheEntry *current_step = base_entry->next;
    while (current_step) {
        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(current_step->re, NULL);
        if (!match_data) {
            fprintf(stderr, "[PCRE] match_data 생성 실패 (체인 베이스='%s')\n", chain_base_id);
            return 0;
        }

        /** 정규식 매칭 시도 */
        int rc = pcre2_match(current_step->re, (PCRE2_SPTR)subject, strlen(subject), 0, 0, match_data, NULL);

        if (rc <= 0) {
            printf("[DEBUG] 체인 단계 매칭 실패 (체인 베이스='%s', 단계='%s')\n", chain_base_id, current_step->rule_id);
            pcre2_match_data_free(match_data);
            return 0;
        }

        /** TX 그룹 캡처 (0부터 시작) */
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        for (int i = 0; i < rc; i++) {
            int start = (int)ovector[2 * i];
            int end = (int)ovector[2 * i + 1];
            int length = end - start;

            if (length > 0 && i < MAX_CAPTURE_GROUPS) {
                /** 캡처된 그룹 복사 */
                char *capture = (char *)malloc(length + 1);
                if (!capture) {
                    fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패\n");
                    pcre2_match_data_free(match_data);
                    return 0;
                }

                strncpy(capture, subject + start, length);
                capture[length] = '\0';
                tx->tx[i] = capture;
                printf("[TX CAPTURE] 그룹 %d: '%s'\n", i, capture);
            }
        }

        /** 다음 단계로 이동 */
        current_step = current_step->next;
        pcre2_match_data_free(match_data);
    }

    printf("[ALERT] 체인 룰 '%s' 매칭 성공 (모든 단계 통과)\n", chain_base_id);
    return 1;
}
