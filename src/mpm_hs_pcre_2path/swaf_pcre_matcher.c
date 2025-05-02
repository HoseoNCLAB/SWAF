#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_matcher.h"
#include "swaf_pcre_cache_table.h"

#include <pcre2.h>
#include <string.h>
#include <stdio.h>

/**
 * SwafMatchPcre
 * - 주어진 룰 ID에 해당하는 정규식을 PCRE2 캐시에서 조회한 뒤,
 * - 입력된 payload 문자열과 매칭시도 후,
 * - 해당 룰이 부정(!@rx)인지 여부에 따라 매칭 결과를 해석
 *  
 * @param rule_id 룰 ID
 * @param payload 입력 문자열
 * @return 1 매칭 성공, 0 매칭 실패
 */
int SwafMatchPcre(const char *rule_id, const char *payload) {
    /* 룰 ID 출력 (디버그용) */
    printf("[DEBUG] 룰 ID 조회 시도: '%s' (len=%zu)\n", rule_id, strlen(rule_id));

    /* 룰 ID에 해당하는 컴파일된 정규식 객체를 캐시에서 가져옴 */
    pcre2_code *re = PcreCacheTableGet(rule_id);
    if (!re) {
        /* 정규식이 존재하지 않을 경우 오류 출력 후 전체 캐시 덤프 */
        fprintf(stderr, "[PCRE] 룰 ID '%s'에 해당하는 정규식 없음\n", rule_id);
        PcreCacheTableDump(PcreCacheTableGetGlobal());
        return 0;
    }

    /* 정규식 매칭을 위한 match_data 구조체 생성 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패\n");
        return 0;
    }

    /*
     * 실제 매칭 수행
     * - re: 컴파일된 정규식
     * - payload: 대상 문자열
     * - rc: 매칭 결과 (0보다 크면 매칭 성공, 0 이하이면 실패)
     */
    int rc = pcre2_match(
        re,
        (PCRE2_SPTR)payload,
        strlen(payload),
        0,              /* 시작 offset */
        0,              /* match 옵션 없음 */
        match_data,
        NULL);          /* context 없음 */

    /* match_data 구조체 해제 */
    pcre2_match_data_free(match_data);

    /* 해당 룰이 부정 매칭인지 여부 확인 */
    int is_negated = PcreCacheTableIsNegated(rule_id);

    /*
     * 결과 해석:
     * - 부정 매칭인 경우: 매칭되지 않아야 성공 → rc <= 0 → 성공
     * - 일반 매칭인 경우: 매칭되어야 성공 → rc > 0 → 성공
     */
    return is_negated ? (rc <= 0) : (rc > 0);
}
