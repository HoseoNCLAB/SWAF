#include "swaf_hs_matcher.h"
#include "mpm.h"
#include "mpm_hs.h"
#include "prefilter.h"
#include "swaf_pcre_matcher.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern MpmCtx mpm_ctx;
static MpmThreadCtx mpm_thread_ctx;

/**
 * SwafMatchHyperscan
 * - Hyperscan 룰 매칭 함수
 * - 입력된 페이로드에 대해 Hyperscan 룰을 매칭하고 결과를 반환
 *
 * @param payload: 입력된 페이로드
 * @return: SigMatchResult 구조체 (매칭된 룰 ID 배열 및 개수 포함)
 * @note: 이 함수는 Hyperscan 룰을 매칭하고, 매칭된 룰 ID를 SigMatchResult 구조체에 저장
 * @note: 매칭된 룰 ID는 SigMatchResult 구조체의 rule_ids 배열에 저장됨
 * @note: 매칭된 룰 개수는 SigMatchResult 구조체의 match_cnt 필드에 저장됨
 */
SigMatchResult SwafMatchHyperscan(const char *payload) {
    SigMatchResult result;
    memset(&result, 0, sizeof(result));

    if (payload == NULL || payload[0] == '\0') {
        fprintf(stderr, "[ERROR] 입력된 페이로드가 비어 있음\n");
        return result;
    }

    size_t len = strnlen(payload, MAX_PAYLOAD_LEN);
    printf("[DEBUG] 페이로드 길이: %lu\n", len);
    printf("[DEBUG] 페이로드 내용: %.*s\n", (int)len, payload);

    memset(&mpm_thread_ctx, 0, sizeof(mpm_thread_ctx));
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    PrefilterRuleStore rule_store;
    memset(&rule_store, 0, sizeof(rule_store));
    if (PmqSetup(&rule_store) != 0) {
        fprintf(stderr, "[ERROR] PmqSetup 실패\n");
        return result;
    }

    printf("[DEBUG] rule_store ID 저장 배열: %p, 크기: %u\n",
           (void *)rule_store.rule_id_array, rule_store.rule_id_array_size);

    uint32_t matched = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &rule_store,   \
                                  (const uint8_t *)payload, (uint32_t)len);

    /** Hyperscan 매칭 성공 시 모든 룰 ID를 결과에 저장 */
    result.match_cnt = rule_store.rule_id_array_cnt;
    if (result.match_cnt > 0 && rule_store.rule_id_array != NULL) {
        memcpy(result.rule_ids, rule_store.rule_id_array,   \
               sizeof(uint32_t) * result.match_cnt);
    }

    PmqCleanup(&rule_store);
    return result;
}
