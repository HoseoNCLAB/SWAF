#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_capture.h"
#include "swaf_pcre_cache_table.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** SwafCapturePcre
 * - 주어진 룰 ID에 해당하는 정규식을 PCRE2 캐시에서 조회한 뒤,
 * - 입력된 subject 문자열과 매칭시도 후,
 * - 캡처된 그룹을 TxStore 구조체에 저장
 *
 * @param rule_id 룰 ID
 * @param subject 입력 문자열
 * @param tx 캡처 결과를 저장할 TxStore 구조체
 * @return 1 캡처 성공, 0 캡처 실패
 */
int SwafCapturePcre(const char *rule_id, const char *subject, TxStore *tx) {
    /* 인자 유효성 검사 */
    if (!rule_id || !subject || !tx) return 0;

    /* 룰 ID에 해당하는 정규식 캐시에서 가져오기 */
    pcre2_code *re = PcreCacheTableGet(rule_id);
    if (!re) {
        fprintf(stderr, "[PCRE] 캡처 실패: 룰 %s 없음\n", rule_id);
        return 0;
    }

    /* 매칭 데이터를 담을 pcre2_match_data 생성 */
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (!match_data) {
        fprintf(stderr, "[PCRE] match_data 생성 실패\n");
        return 0;
    }

    /* 정규식 매칭 수행 */
    int rc = pcre2_match(
        re,                         /* 정규식 객체 */
        (PCRE2_SPTR)subject,        /* 입력 문자열 */
        strlen(subject),            /* 문자열 길이 */
        0,                          /* 시작 오프셋 */
        0,                          /* 옵션 없음 */
        match_data,                 /* 매칭 결과 저장 */
        NULL);                      /* context 없음 */

    /* 매칭 실패 시 종료 */
    if (rc <= 0) {
        pcre2_match_data_free(match_data);
        return 0;
    }

    /*
     * ovector: 매칭된 구간의 시작/끝 인덱스를 담고 있는 배열
     * - ovector[0]: 첫 번째 매칭 시작 인덱스
     * - ovector[1]: 첫 번째 매칭 끝 인덱스
     * - ovector[2]: 두 번째 매칭 시작 ...
     */
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

    /* 각 캡처 그룹별로 문자열 복사 */
    for (int i = 0; i < rc && i < MAX_CAPTURE_GROUPS; ++i) {
        PCRE2_SIZE start = ovector[2 * i];
        PCRE2_SIZE end   = ovector[2 * i + 1];
        size_t len = end - start;

        /* 최대 길이 제한 */
        if (len >= MAX_CAPTURE_LEN)
            len = MAX_CAPTURE_LEN - 1;

        /* 기존 저장값이 있으면 해제 */
        if (tx->tx[i]) free(tx->tx[i]);

        /* 새로운 캡처 문자열 저장을 위한 메모리 할당 */
        tx->tx[i] = (char *)malloc(len + 1);
        if (!tx->tx[i]) {
            fprintf(stderr, "[PCRE] 캡처 메모리 할당 실패 (TX.%d)\n", i);
            continue;
        }

        /* 캡처된 문자열 복사 및 널 종료 */
        strncpy(tx->tx[i], subject + start, len);
        tx->tx[i][len] = '\0';
    }

    /* 매칭 데이터 해제 */
    pcre2_match_data_free(match_data);
    return 1;
}
