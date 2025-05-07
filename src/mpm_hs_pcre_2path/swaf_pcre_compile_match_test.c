#include <stdio.h>
#include <string.h>

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_matcher.h"
#include "swaf_pcre_capture_single.h"
#include "swaf_pcre_capture_chain.h"
#include "tx_store.h"

#define PCRE_RULE_PATH "../../parsed_rules/pcre_only_rules.json"

int main() {
    /** 1. 캐시 및 룰 초기화 */
    if (PcreCacheTableInit() != 0) {
        fprintf(stderr, "[TEST] PCRE 캐시 초기화 실패\n");
        return 1;
    }

    if (SwafInitPCRE(PCRE_RULE_PATH) != 0) {
        fprintf(stderr, "[TEST] PCRE 룰 로딩 실패\n");
        return 1;
    }

    /** 2. 테스트할 룰 ID와 페이로드 */
    // const char *rule_id = "942130";  // 체인 룰 ID
    // const char *payload = "username = admin AND password != 1234 AND substr(password,1,3)";

    // const char *rule_id = "941160";  // 단일 룰 ID
    // const char *payload = "<script>alert('XSS')</script>";  // 테스트할 페이로드

    // RCE 체인 룰 테스트
    const char *rule_id = "932200";  // 체인 룰 ID
    const char *payload = "/bin/sh -c \"$(echo 'echo hello') && cat $HOME/.bashrc | grep root";


    printf("[TEST] 룰 %s 에 대한 매칭 시도\n", rule_id);

    /** 3. 체인 룰 여부 판단 (_0 존재 여부로 확인) */
    char chain_id[64];
    snprintf(chain_id, sizeof(chain_id), "%s_0", rule_id);

    TxStore tx = {0};  // 캡처 결과 저장용

    /* 매칭 전 디버그 */
    printf("[DEBUG] PCRE 입력 문자열: '%s'\n", payload);
    printf("[DEBUG] 정규식 길이: %zu\n", strlen(payload));

    if (PcreCacheTableGet(chain_id)) {
        /** 체인 룰 처리 */
        if (SwafMatchPcreChain(rule_id, payload)) {
            printf("[RESULT] 체인 룰 매칭 성공\n");

            if (SwafCapturePcreChain(rule_id, payload, &tx)) {
                for (int i = 0; i < MAX_CAPTURE_GROUPS; i++) {
                    if (tx.tx[i])
                        printf("TX.%d = %s\n", i, tx.tx[i]);
                }
            }
        } else {
            printf("[RESULT] 체인 룰 매칭 실패\n");
        }
    } else {
        /** 단일 룰 처리 */
        printf("[DEBUG] SwafMatchPcre 호출: 룰 ID = [%s] (len=%zu)\n", rule_id, strlen(rule_id));
        if (SwafMatchPcre(rule_id, payload)) {
            printf("[RESULT] 매칭 성공\n");

            if (SwafCapturePcre(rule_id, payload, &tx)) {
                for (int i = 0; i < MAX_CAPTURE_GROUPS; i++) {
                    if (tx.tx[i])
                        printf("TX.%d = %s\n", i, tx.tx[i]);
                }
            }
        } else {
            printf("[RESULT] 매칭 실패\n");
        }
    }

    return 0;
}
