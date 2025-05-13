#include <stdio.h>
#include <string.h>

#include "swaf_hs_loader.h"
#include "swaf_hs_matcher.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_loader.h"
#include "swaf_pcre_matcher.h"
#include "swaf_pcre_capture_chain.h"
#include "swaf_pcre_capture_single.h"
#include "tx_store.h"

#define HS_ONLY_RULE_PATH   "../../parsed_rules/hyperscan_only_rules.json"
#define PCRE_ONLY_RULE_PATH "../../parsed_rules/pcre_only_rules.json"

int main() {
    printf("[SWAF] Hyperscan/PCRE 초기화 시작\n");

    // 1. Hyperscan 초기화
    if (SwafInitHyperscan(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] Hyperscan DB 컴파일 실패\n");
        return 1;
    }

    if (SwafConnectPatternSids() != 0) {
        fprintf(stderr, "[SWAF] SID 연결 실패\n");
        return 1;
    }

    // 2. PCRE 캐시 초기화
    if (PcreCacheTableInit() != 0) {
        fprintf(stderr, "[SWAF] PCRE 캐시 초기화 실패\n");
        return 1;
    }

    // 3. HS-only 및 PCRE-only 룰 초기화
    if (SwafInitHsOnly(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] HS-only 룰 로딩 실패\n");
        return 1;
    }

    if (SwafInitPcreOnly(PCRE_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] PCRE-only 룰 로딩 실패\n");
        return 1;
    }

    printf("[SWAF] 초기화 완료\n");

    // 4. 사용자 입력 기반 매칭 루프
    char payload[8192] = {0,};
    while (1) {
        memset(payload, 0, sizeof(payload));

        printf("\n[INPUT] 페이로드 입력 > ");
        if (!fgets(payload, sizeof(payload), stdin))
            break;

        payload[strcspn(payload, "\n")] = '\0';

        // 1단계: Hyperscan 매칭
        SigMatchResult result = SwafMatchHyperscan(payload);

        if (result.match_cnt > 0) {
            printf("\n[INFO] Hyperscan 탐지된 룰 %d개\n", result.match_cnt);
            for (int i = 0; i < result.match_cnt; ++i) {
                printf("  - SID: %u (PCRE로 TX 캡처 시도)\n", result.rule_ids[i]);
            }
        } else {
            // Hyperscan 미탐지 시 → PCRE-only 룰 전체 매칭 시도
            printf("[INFO] Hyperscan 미탐지 → PCRE-only 매칭 시도 중...\n");

            int matched = 0;
            PcreCacheTable *pcre_cache = PcreOnlyCacheTableGetGlobal();
            if (!pcre_cache) {
                fprintf(stderr, "[ERROR] PCRE-only 캐시 테이블 없음\n");
                continue;
            }

            for (uint32_t i = 0; i < pcre_cache->size; i++) {
                Bucket *bucket = pcre_cache->buckets[i];
                while (bucket) {
                    TxStore tx;
                    InitTxStore(&tx);

                    if (SwafPcreMatchWithId(payload, strlen(payload), atoi(bucket->key), &tx)) {
                        matched = 1;
                        printf("[ALERT] PCRE-only 룰 매칭됨: %s\n", bucket->key);
                    }

                    FreeTxStore(&tx);
                    bucket = bucket->next;
                }
            }

            if (!matched)
                printf("[RESULT] 탐지된 룰 없음 (정상 트래픽)\n");
        }
    }

    return 0;
}
