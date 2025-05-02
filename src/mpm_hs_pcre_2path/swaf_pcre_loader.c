#define PCRE2_CODE_UNIT_WIDTH 8  /* PCRE2 정규식에서 사용할 단위 폭 (8비트 = UTF-8) */

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"

#include <jansson.h>
#include <pcre2.h>
#include <stdio.h>
#include <string.h>


 /**
  * SwafInitPCRE
  * - JSON 형식의 PCRE 룰 파일을 파싱하고, 
  * - 각 정규식을 PCRE2로 컴파일한 후,
  * - 글로벌 캐시에 등록
  *
  * @param json_path JSON 파일 경로
  * @return 0 성공, -1 실패
  */
int SwafInitPCRE(const char *json_path) {
    json_error_t error;

    /* JSON 파일 로딩 */
    json_t *root = json_load_file(json_path, 0, &error);
    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[PCRE] JSON 파싱 실패: %s\n", error.text);
        return -1;
    }

    const char *rule_id;
    json_t *rule_obj;

    /* 각 룰 ID에 대한 객체 순회 */
    json_object_foreach(root, rule_id, rule_obj) {
        /* 체인 룰인 경우 (배열 형태)는 스킵 */
        if (json_is_array(rule_obj)) {
            size_t chain_len = json_array_size(rule_obj);
            printf("[CHAIN] 룰 %s: 총 %zu단계 체인 룰 구성됨\n", rule_id, chain_len);
            for (size_t i = 0; i < chain_len; ++i) {
                json_t *step = json_array_get(rule_obj, i);
                const char *rx = json_string_value(json_object_get(step, "regex"));
                printf("[CHAIN]   - [%zu단계] regex 길이: %zu\n", i, rx ? strlen(rx) : 0);
            }
            continue;
        }

        /* object가 아닌 경우 오류 처리 */
        if (!json_is_object(rule_obj)) {
            fprintf(stderr, "[PCRE] 잘못된 형식: %s\n", rule_id);
            continue;
        }

        /* 정규식 추출 */
        const char *regex_raw = json_string_value(json_object_get(rule_obj, "regex"));
        if (!regex_raw) {
            fprintf(stderr, "[PCRE] regex 누락: %s\n", rule_id);
            continue;
        }

        /* 정규식에서 부정 매칭 여부 확인 (!@rx) */
        int is_negated = 0;
        const char *actual_rx = NULL;

        if (strncmp(regex_raw, "!@rx", 4) == 0) {
            is_negated = 1;
            actual_rx = regex_raw + 4;
        } else if (strncmp(regex_raw, "@rx", 3) == 0) {
            is_negated = 0;
            actual_rx = regex_raw + 3;
        } else {
            actual_rx = regex_raw;  /* fallback 처리 */
        }

        /* 앞쪽 공백 제거 */
        while (*actual_rx == ' ') actual_rx++;

        /* 디버그 출력 */
        size_t len = strlen(actual_rx);
        printf("[DEBUG] 룰 %s → 정규식 길이: %zu, 체인: false, 부정 매칭: %s\n",
               rule_id, len, is_negated ? "true" : "false");

        /* 정규식 컴파일 */
        int errornum;
        PCRE2_SIZE erroffset;
        pcre2_code *re = pcre2_compile(
            (PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, 0,
            &errornum, &erroffset, NULL);

        /* 컴파일 실패 시 에러 메시지 출력 */
        if (!re) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornum, buffer, sizeof(buffer));
            fprintf(stderr, "[ERROR] 컴파일 실패 (%s): %s\n", rule_id, buffer);
            continue;
        }

        /* 캐시에 추가 */
        printf("[DEBUG] PcreCacheAdd 등록: 룰 ID = [%s] (len=%zu)\n", rule_id, strlen(rule_id));
        if (PcreCacheTableAdd(rule_id, re, is_negated) != 0) {
            fprintf(stderr, "[PCRE] 캐시에 추가 실패: %s\n", rule_id);
            pcre2_code_free(re);
            continue;
        }

        /* 성공 출력 */
        printf("[DEBUG] 컴파일 성공: %s\n", rule_id);
    }

    /* JSON 메모리 해제 */
    json_decref(root);
    return 0;
}
