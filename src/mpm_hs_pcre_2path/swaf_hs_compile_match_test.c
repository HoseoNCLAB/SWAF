#include <stdio.h>
#include <string.h>
#include "swaf_hs_loader.h"
#include "swaf_hs_matcher.h"

#define HS_RULE_PATH "../parsed_rules/hyperscan_only_rules.json"

int main() {
    printf("[SWAF] Hyperscan DB 컴파일 테스트 시작\n");

    if (SwafInitHyperscan(HS_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] Hyperscan DB 컴파일 실패\n");
        return 1;
    }

    if (SwafConnectPatternSids() != 0) {
        fprintf(stderr, "[SWAF] SID 연결 실패\n");
        return 1;
    }

    printf("[SWAF] Hyperscan DB 컴파일 성공\n");

    // 사용자 입력 기반 매칭 루프
    char payload[8192];
    while (1) {
        printf("\n[INPUT] 페이로드 입력 > ");
        if (!fgets(payload, sizeof(payload), stdin))
            break;

        payload[strcspn(payload, "\n")] = '\0';

        SigMatchResult result = SwafMatchHyperscan(payload);
        if (result.match_cnt == 0) {
            printf("[RESULT] 탐지된 룰 없음 (정상 트래픽)\n");
        } else {
            printf("[ALERT] 탐지된 룰 %d개:\n", result.match_cnt);
            for (int i = 0; i < result.match_cnt; ++i) {
                printf("  - SID: %u\n", result.rule_ids[i]);
            }
        }
    }

    return 0;
}
