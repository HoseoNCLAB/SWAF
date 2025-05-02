#include "swaf_hs_matcher.h"
#include "mpm.h"
#include "mpm_hs.h"
#include "prefilter.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern MpmCtx mpm_ctx;  // swaf_hs_loader.c에서 초기화된 글로벌 컨텍스트

// 전역 스레드 컨텍스트 (1회 초기화 재사용 가능)
static MpmThreadCtx mpm_thread_ctx;

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

    // 핵심 수정: len은 최대 MAX_PAYLOAD_LEN까지만 전달
    uint32_t matched = SCHSSearch(&mpm_ctx,
                                  &mpm_thread_ctx,
                                  &rule_store,
                                  (const uint8_t *)payload,
                                  (uint32_t)len);

    if (rule_store.rule_id_array_cnt > rule_store.rule_id_array_size) {
        fprintf(stderr, "[FATAL] rule_id_array_cnt (%u) > rule_id_array_size (%u)\n",
                rule_store.rule_id_array_cnt, rule_store.rule_id_array_size);
        PmqCleanup(&rule_store);
        exit(EXIT_FAILURE);
    }

    printf("[DEBUG] 매칭된 룰 개수: %u\n", rule_store.rule_id_array_cnt);
    for (uint32_t i = 0; i < rule_store.rule_id_array_cnt; i++) {
        printf("  - rule_id_array[%u] = %u\n", i, rule_store.rule_id_array[i]);
    }

    result.match_cnt = rule_store.rule_id_array_cnt;
    if (result.match_cnt > 0 && rule_store.rule_id_array != NULL) {
        memcpy(result.rule_ids,
               rule_store.rule_id_array,
               sizeof(uint32_t) * result.match_cnt);
    }

    PmqCleanup(&rule_store);
    return result;
}
