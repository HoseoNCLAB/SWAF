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

//#define HS_ONLY_RULE_PATH   "../../parsed_rules/hyperscan_only_rules.json"
//#define PCRE_ONLY_RULE_PATH "../../parsed_rules/pcre_only_rules.json"
#define HS_ONLY_RULE_PATH   "../../parsed_rules/hs_only_rules_for_test_chain.json"
#define PCRE_ONLY_RULE_PATH "../../parsed_rules/pcre_only_rules_for_test.json"


/**
 * 메인 함수
 * - Hyperscan 및 PCRE 초기화
 * - 사용자 입력 페이로드에 대해 매칭 수행
 * - HS-only, PCRE-only, 체인 룰 처리
 */
int main() {
    printf("[SWAF] Hyperscan/PCRE 초기화 시작\n");

    /** 1. Hyperscan 초기화 */
    if (SwafInitHyperscan(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] Hyperscan DB 컴파일 실패\n");
        return 1;
    }

    if (SwafConnectPatternSids() != 0) {
        fprintf(stderr, "[SWAF] SID 연결 실패\n");
        return 1;
    }

    /** 2. PCRE 캐시 초기화 (체인 캐시 포함) */
    if (PcreCacheTableInit() != 0) {
        fprintf(stderr, "[SWAF] 글로벌 캐시 테이블 초기화 실패\n");
        return 1;
    }

    /** 3. HS-only 룰 초기화 */
    if (SwafInitHsOnly(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] HS-only 룰 로딩 실패\n");
        PcreCacheTableFree();
        return 1;
    }

    /** 4. PCRE-only 룰 초기화 (체인 룰 포함) */
    if (SwafInitPcreOnly(PCRE_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] PCRE-only 룰 로딩 실패\n");
        PcreCacheTableFree();
        return 1;
    }

    /** 캐시 테이블 상태 출력 */
    printf("\n=== PCRE 캐시 테이블 상태 ===\n");
    printf("\n[DEBUG] HS-Cache:\n");
    PcreCacheTableDump(HsCacheTableGetGlobal());

    printf("\n[DEBUG] PCRE-Only Cache:\n");
    PcreCacheTableDump(PcreOnlyCacheTableGetGlobal());

    printf("\n[DEBUG] Chain Cache:\n");
    PcreCacheTableDump(ChainCacheTableGetGlobal());

    /** 최종 초기화 완료 메시지 */
    printf("[SWAF] 초기화 완료 (HS, PCRE, Chain 룰 로딩 완료)\n");

    /** 사용자 입력 기반 매칭 루프 */
    char payload[8192] = {0};
    while (1) {
        memset(payload, 0, sizeof(payload));

        printf("\n[INPUT] 페이로드 입력 > ");
        if (!fgets(payload, sizeof(payload), stdin))
            break;

        /** 줄바꿈 문자 제거 */
        payload[strcspn(payload, "\n")] = '\0';

        /** 1단계: Hyperscan 매칭 */
        SigMatchResult result = SwafMatchHyperscan(payload);
        int pcre_match_count = 0;       /** PCRE 매칭된 룰 개수 */

        /** 1. Hyperscan 매칭 결과 처리 */
        if (result.match_cnt > 0) {
            printf("\n[INFO] Hyperscan 탐지된 룰 %d개\n", result.match_cnt);
            for (int i = 0; i < result.match_cnt; ++i) {
                printf("  - SID: %u (PCRE로 TX 캡처 시도)\n", result.rule_ids[i]);

                TxStore tx;
                InitTxStore(&tx);

                /** Hyperscan 탐지된 룰에 대해 PCRE 매칭 시도 */
                if (SwafPcreMatchWithId(payload, strlen(payload), result.rule_ids[i], &tx)) {
                    printf("[ALERT] Hyperscan 매칭된 룰 %u에 대해 PCRE 캡처 성공\n", result.rule_ids[i]);
                }

                FreeTxStore(&tx);
            }
        } 
        /** 2. Hyperscan 미탐지 시 PCRE-only 룰 처리 */
        else {
            printf("\n[INFO] Hyperscan 미탐지 → PCRE-only 매칭 시도 중...\n");

            int matched = 0;
            int negated_only_count = 0;
            int total_matched_count = 0;
            PcreCacheTable *pcre_cache = PcreOnlyCacheTableGetGlobal();
            if (!pcre_cache) {
                fprintf(stderr, "[ERROR] PCRE-only 캐시 테이블 없음\n");
                continue;
            }

            /** 단일 PCRE 룰 매칭 */
            for (uint32_t i = 0; i < pcre_cache->size; i++) {
                Bucket *bucket = pcre_cache->buckets[i];
                while (bucket) {
                    TxStore tx;
                    InitTxStore(&tx);

                    /** 단일 룰 매칭 시도 */
                    if (SwafMatchPcreSingle(bucket->key, payload, &tx)) {
                        matched = 1;
                        pcre_match_count++;
                        total_matched_count++;
                        PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(pcre_cache, bucket->key, strlen(bucket->key));
                        if (entry && entry->is_negated)
                            negated_only_count++;
                    }

                    FreeTxStore(&tx);
                    bucket = bucket->next;
                }
            }

            /** 체인 룰 매칭 */
            PcreCacheTable *chain_cache = ChainCacheTableGetGlobal();
            for (uint32_t i = 0; i < chain_cache->size; i++) {
                Bucket *bucket = chain_cache->buckets[i];
                while (bucket) {
                    TxStore tx;
                    InitTxStore(&tx);

                    /** 체인 룰 매칭 시도 */
                    if (SwafCapturePcreChain(bucket->key, payload, &tx)) {
                        matched = 1;
                        pcre_match_count++;
                        printf("[ALERT] 체인 PCRE 룰 매칭됨: %s\n", bucket->key);
                    }

                    FreeTxStore(&tx);
                    bucket = bucket->next;
                }
            }

            printf("\n[INFO] PCRE 탐지된 룰 %d개\n", pcre_match_count);
            if (negated_only_count > 0)
                printf("[INFO] (부정 매칭 룰 탐지 %d개)\n", negated_only_count);

            /**
            * 모든 단일 부정 매칭 룰이 "성공"한 경우만 정상 트래픽으로 간주
            * (즉, 전체 부정 매칭 룰 개수 == negated_only_count)
            * 하나라도 실패(악성)면 정상 트래픽 아님
            */
            int total_negated_rules = 0;
            for (uint32_t i = 0; i < pcre_cache->size; i++) {
                Bucket *bucket = pcre_cache->buckets[i];
                while (bucket) {
                    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(pcre_cache, bucket->key, strlen(bucket->key));
                    if (entry && entry->is_negated)
                        total_negated_rules++;
                    bucket = bucket->next;
                }
            }

            if (!matched || (total_negated_rules > 0 && total_negated_rules == negated_only_count && total_matched_count == negated_only_count)) {
                printf("[RESULT] 탐지된 룰 없음 (정상 트래픽)\n");
            } else {
                printf("[RESULT] 악성 트래픽 탐지됨\n");
            }
        }
    }
    /** 5. 리소스 해제 */
    printf("\n[INFO] 프로그램 종료\n");
    return 0;
}
