#define PCRE2_CODE_UNIT_WIDTH 8  /* PCRE2 정규식에서 사용할 단위 폭 (8비트 = UTF-8) */

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"

#include <jansson.h>
#include <pcre2.h>
#include <stdio.h>
#include <string.h>

/**
 * SwafInitPCRE
 * 
 * - JSON에 정의된 PCRE 룰셋을 파싱하여
 * - 정규식을 컴파일하고
 * - PCRE 캐시에 등록하는 초기화 함수
 *
 * @param json_path JSON 파일 경로
 * @return 0 (성공), -1 (실패)
 */
int SwafInitPCRE(const char *json_path) {
    json_error_t error;
    json_t *root = json_load_file(json_path, 0, &error);

    /* JSON 파싱 실패 시 에러 출력 후 종료 */
    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[PCRE] JSON 파싱 실패: %s\n", error.text);
        return -1;
    }

    const char *rule_id;
    json_t *rule_obj;

    /* 전체 JSON 객체 순회 (rule_id → rule_obj) */
    json_object_foreach(root, rule_id, rule_obj) {

        /** ---------------- 체인 룰 처리 ---------------- 
         * 체인 룰은 JSON 배열로 정의됨
         * 예: "942130": [ { "regex": "@rx ..."}, { "regex": "@rx ..." } ]
         * 각 단계는 고유 ID를 붙여서 캐시에 등록됨
         * 예: "942130_0", "942130_1", ...
         */
        if (json_is_array(rule_obj)) {
            size_t chain_len = json_array_size(rule_obj);
            printf("[CHAIN] 룰 %s: 총 %zu단계 체인 룰 구성됨\n", rule_id, chain_len);

            for (size_t i = 0; i < chain_len; ++i) {
                json_t *step = json_array_get(rule_obj, i);
                const char *regex_raw = json_string_value(json_object_get(step, "regex"));

                /* regex 누락 시 경고 출력 후 스킵 */
                if (!regex_raw) {
                    fprintf(stderr, "[PCRE] 체인[%s_%zu] regex 누락\n", rule_id, i);
                    continue;
                }

                /* @rx 또는 !@rx 접두사 확인 및 부정 매칭 처리 */
                int is_negated = 0;
                const char *actual_rx = NULL;

                if (strncmp(regex_raw, "!@rx", 4) == 0) {
                    is_negated = 1;
                    actual_rx = regex_raw + 4;
                } else if (strncmp(regex_raw, "@rx", 3) == 0) {
                    actual_rx = regex_raw + 3;
                } else {
                    actual_rx = regex_raw;
                }

                /* 정규식 앞 공백 제거 */
                while (*actual_rx == ' ') actual_rx++;

                /* 정규식 길이 출력 */
                size_t len = strlen(actual_rx);
                printf("[CHAIN]   - [%zu단계] regex 길이: %zu\n", i, len);

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
                    fprintf(stderr, "[ERROR] 체인 컴파일 실패 (%s_%zu): %s\n", rule_id, i, buffer);
                    continue;
                }

                /* "942130_0" 같은 체인 룰 ID 생성 및 캐시 등록 */
                char chain_id[64];
                snprintf(chain_id, sizeof(chain_id), "%s_%zu", rule_id, i);
                printf("[DEBUG] PcreCacheAdd 등록: 룰 ID = [%s] (len=%zu)\n", chain_id, strlen(chain_id));

                if (PcreCacheTableAdd(chain_id, re, is_negated) != 0) {
                    fprintf(stderr, "[PCRE] 체인 캐시 추가 실패: %s\n", chain_id);
                    pcre2_code_free(re);
                    continue;
                }

                printf("[DEBUG] 체인 컴파일 성공: %s\n", chain_id);
            }

            /* 이 룰은 체인 룰이므로 다음으로 넘어감 */
            continue;
        }

        /** ---------------- 단일 룰 처리 ----------------
         * 단일 룰은 JSON 객체로 정의됨
         * 예: "920275": { "regex": "@rx ..." }
         * 이 경우는 룰 ID가 그대로 사용됨
         */
        if (!json_is_object(rule_obj)) {
            fprintf(stderr, "[PCRE] 잘못된 형식: %s\n", rule_id);
            continue;
        }

        /* regex 필드 추출 */
        const char *regex_raw = json_string_value(json_object_get(rule_obj, "regex"));
        if (!regex_raw) {
            fprintf(stderr, "[PCRE] regex 누락: %s\n", rule_id);
            continue;
        }

        /* @rx 또는 !@rx 접두사 확인 및 부정 매칭 처리 */
        int is_negated = 0;
        const char *actual_rx = NULL;

        if (strncmp(regex_raw, "!@rx", 4) == 0) {
            is_negated = 1;
            actual_rx = regex_raw + 4;
        } else if (strncmp(regex_raw, "@rx", 3) == 0) {
            actual_rx = regex_raw + 3;
        } else {
            actual_rx = regex_raw;
        }

        /* 정규식 앞 공백 제거 */
        while (*actual_rx == ' ') actual_rx++;

        /* 디버그 출력 (정규식 길이, 부정 여부) */
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

        /* 룰 ID로 캐시에 등록 */
        printf("[DEBUG] PcreCacheAdd 등록: 룰 ID = [%s] (len=%zu)\n", rule_id, strlen(rule_id));
        if (PcreCacheTableAdd(rule_id, re, is_negated) != 0) {
            fprintf(stderr, "[PCRE] 캐시에 추가 실패: %s\n", rule_id);
            pcre2_code_free(re);
            continue;
        }

        printf("[DEBUG] 컴파일 성공: %s\n", rule_id);
    }

    /* JSON 객체 해제 */
    json_decref(root);
    return 0;
}
