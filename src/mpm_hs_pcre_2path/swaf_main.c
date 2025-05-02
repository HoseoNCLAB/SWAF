#include <stdio.h>
#include <string.h>

#include "swaf_hs_loader.h"
#include "swaf_hs_matcher.h"
#include "swaf_pcre_cache.h"
#include "swaf_pcre_loader.h"
#include "swaf_pcre_matcher.h"
#include "swaf_pcre_capture.h"
#include "tx_store.h"

#define HS_ONLY_RULE_PATH   "../../parsed_rules/hyperscan_only_rules.json"
#define PCRE_ONLY_RULE_PATH "../../parsed_rules/pcre_only_rules.json"

extern char **GetAllPcreRuleIds(int *count); // swaf_pcre_loader.c 내부 구현 필요

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

    // 2. PCRE 초기화
    if (PcreCacheInit() != 0) {
        fprintf(stderr, "[SWAF] PCRE 캐시 초기화 실패\n");
        return 1;
    }

    if (SwafInitPCRE(PCRE_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] PCRE 룰 로딩 실패\n");
        return 1;
    }

    printf("[SWAF] 초기화 완료\n");

    // 3. 사용자 입력 기반 매칭 루프
    char payload[8192] = {0,};
    while (1) {
        memset(payload, 0, sizeof(payload));

        printf("\n[INPUT] 페이로드 입력 > ");
        if (!fgets(payload, sizeof(payload), stdin))
            break;

        payload[strcspn(payload, "\n")] = '\0';

        SigMatchResult result = SwafMatchHyperscan(payload);

        if (result.match_cnt > 0) {
            printf("[ALERT] Hyperscan 탐지된 룰 %d개:\n", result.match_cnt);
            for (int i = 0; i < result.match_cnt; ++i) {
                printf("  - SID: %u (PCRE로 TX 캡처 시도)\n", result.rule_ids[i]);

                char rule_id_str[16];
                snprintf(rule_id_str, sizeof(rule_id_str), "%u", result.rule_ids[i]);

                TxStore tx = {0};
                if (SwafCapturePcre(rule_id_str, payload, &tx)) {
                    for (int j = 0; j < MAX_CAPTURE_GROUPS; j++) {
                        if (tx.tx[j])
                            printf("    TX.%d = %s\n", j, tx.tx[j]);
                    }
                }
            }
        } else {
            // Hyperscan 미탐지 시 → PCRE-only 룰 전체 매칭 시도
            printf("[INFO] Hyperscan 미탐지 → PCRE-only 매칭 시도 중...\n");

            int pcre_rule_cnt = 0;
            char **rule_ids = GetAllPcreRuleIds(&pcre_rule_cnt); // 이 함수는 PCRE JSON 전체 rule_id 반환

            int matched = 0;
            for (int i = 0; i < pcre_rule_cnt; ++i) {
                if (SwafMatchPcre(rule_ids[i], payload)) {
                    matched = 1;
                    printf("[ALERT] PCRE-only 룰 매칭됨: %s\n", rule_ids[i]);

                    TxStore tx = {0};
                    if (SwafCapturePcre(rule_ids[i], payload, &tx)) {
                        for (int j = 0; j < MAX_CAPTURE_GROUPS; j++) {
                            if (tx.tx[j])
                                printf("    TX.%d = %s\n", j, tx.tx[j]);
                        }
                    }
                }
            }

            if (!matched)
                printf("[RESULT] 탐지된 룰 없음 (정상 트래픽)\n");

            free(rule_ids);
        }
    }

    return 0;
}

