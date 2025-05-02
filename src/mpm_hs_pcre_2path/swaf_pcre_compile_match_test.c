#include <stdio.h>
#include <string.h>

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_matcher.h"
#include "swaf_pcre_capture.h"
#include "tx_store.h"

#define PCRE_RULE_PATH "../../parsed_rules/pcre_only_rules.json"

int main() {
    // 1. 캐시 및 룰 초기화
    if (PcreCacheTableInit() != 0) {
        fprintf(stderr, "[TEST] PCRE 캐시 초기화 실패\n");
        return 1;
    }

    if (SwafInitPCRE(PCRE_RULE_PATH) != 0) {
        fprintf(stderr, "[TEST] PCRE 룰 로딩 실패\n");
        return 1;
    }

    // 2. 테스트할 rule_id와 payload
    const char *rule_id = "920275";  // 실제 JSON에 있는 룰 ID로 바꾸세요
    const char *payload = "@@garbage^";

    // 3. 매칭 테스트
    printf("[TEST] 룰 %s 에 대한 매칭 시도\n", rule_id);
    printf("[DEBUG] SwafMatchPcre 호출: 룰 ID = [%s] (len=%zu)\n", rule_id, strlen(rule_id));
    if (SwafMatchPcre(rule_id, payload)) {
        printf("[RESULT] 매칭 성공\n");

        TxStore tx = {0};
        if (SwafCapturePcre(rule_id, payload, &tx)) {
            for (int i = 0; i < MAX_CAPTURE_GROUPS; i++) {
                if (tx.tx[i])
                    printf("TX.%d = %s\n", i, tx.tx[i]);
            }
        }
    } else {
        printf("[RESULT] 매칭 실패\n");
    }

    return 0;
}

