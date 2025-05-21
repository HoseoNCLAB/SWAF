#include "swaf_hot_reload.h"
#include "swaf_hs_loader.h"
#include "swaf_pcre_cache_table.h"
#include "swaf_pcre_loader.h"

#include "mpm.h"           /** for mpm_ctx */
#include "mpm_hs.h"        /** for SCHSFreeCtx */
#include "mpm_hs_core.h"   /** for PmqFree */

#include <stdio.h>

#define HS_ONLY_RULE_PATH   "../../parsed_rules/hyperscan_only_rules.json"
#define PCRE_ONLY_RULE_PATH "../../parsed_rules/pcre_only_rules.json"

extern MpmCtx mpm_ctx;

/**
 * SWAF 엔진 언로드 함수
 * - Hyperscan, PCRE 룰 및 메모리 캐시 정리
 */
void SwafUnloadRules(void) {
    printf("[SWAF] unloading previous rules...\n");

    /** Hyperscan 리소스 정리 */
    SCHSFreeCtx(&mpm_ctx);   /** Hyperscan ctx 내부의 DB, scratch 등 해제 */
    PmqFree(&mpm_ctx);       /** SID 매핑 테이블 해제 */

    /** PCRE 캐시 정리 */
    PcreCacheTableFree();

    printf("[SWAF] previous rules unloaded\n");
}


/**
 * CRS 룰 재로드 함수
 * - 기존 Hyperscan DB 및 PCRE 캐시를 해제하고,
 *   최신 JSON 파일을 기반으로 룰을 다시 로딩 및 초기화
 *
 * @return 0: 성공, -1: 실패
 */
int SwafReloadRules(void) {
    printf("[SWAF] start hot-reload\n");

    /** 기존 리소스 언로드 */
    SwafUnloadRules();

    /** Hyperscan 룰 초기화 */
    if (SwafInitHyperscan(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] Hyperscan DB 재컴파일 실패\n");
        return -1;
    }

    if (SwafConnectPatternSids() != 0) {
        fprintf(stderr, "[SWAF] SID 재연결 실패\n");
        return -1;
    }

    /** PCRE 캐시 테이블 초기화 */
    if (PcreCacheTableInit() != 0) {
        fprintf(stderr, "[SWAF] 글로벌 캐시 테이블 재초기화 실패\n");
        return -1;
    }

    /** Hyperscan 전용 룰 로딩 */
    if (SwafInitHsOnly(HS_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] HS-only 룰 재로딩 실패\n");
        PcreCacheTableFree();
        return -1;
    }

    /** PCRE-only 룰 로딩 */
    if (SwafInitPcreOnly(PCRE_ONLY_RULE_PATH) != 0) {
        fprintf(stderr, "[SWAF] PCRE-only 룰 재로딩 실패\n");
        PcreCacheTableFree();
        return -1;
    }

    printf("[SWAF] finish hot-reload\n");
    return 0;
}