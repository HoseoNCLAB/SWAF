#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"

#include <jansson.h>
#include <pcre2.h>
#include <stdio.h>
#include <string.h>

/**
 * SwafInitHsOnly
 * - HS-only 룰을 초기화하는 함수
 * - JSON 파일 경로를 인자로 받아서 룰을 로드
 *
 * @param json_path: JSON 파일 경로
 * @return: 0 (성공), -1 (실패)
 * @note: 이 함수는 HS-only 룰을 초기화하고, 룰을 로드하여 캐시 테이블에 저장
 */
int SwafInitHsOnly(const char *json_path) {
    json_error_t error;
    json_t *root = json_load_file(json_path, 0, &error);

    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[HS-ONLY] JSON 파싱 실패: %s\n", error.text);
        return -1;
    }

    const char *rule_id;
    json_t *rule_obj;

    json_object_foreach(root, rule_id, rule_obj) {
        const char *regex_raw = json_string_value(json_object_get(rule_obj, "regex"));
        if (!regex_raw) {
            fprintf(stderr, "[HS-ONLY] regex 누락: %s\n", rule_id);
            continue;
        }

        int is_negated = 0;
        const char *actual_rx = regex_raw;
        if (strncmp(regex_raw, "!@rx", 4) == 0) {
            is_negated = 1;
            actual_rx = regex_raw + 4;
        } else if (strncmp(regex_raw, "@rx", 3) == 0) {
            actual_rx = regex_raw + 3;
        }

        while (*actual_rx == ' ') actual_rx++;

        int errornum;
        PCRE2_SIZE erroffset;
        pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, \
                                        0, &errornum, &erroffset, NULL);

        if (!re) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornum, buffer, sizeof(buffer));
            fprintf(stderr, "[HS-ONLY] 컴파일 실패 (%s): %s\n", rule_id, buffer);
            continue;
        }

        /** HS-only 룰은 PCRE 캐시 테이블에 추가 */
        if (PcreCacheTableAddToHsCache(rule_id, re, is_negated) != 0) {
            fprintf(stderr, "[HS-ONLY] 캐시 추가 실패: %s\n", rule_id);
            pcre2_code_free(re);
            continue;
        }

        printf("[DEBUG] HS-only 룰 로딩 성공: %s (negated=%d)\n", rule_id, is_negated);
    }

    json_decref(root);
    return 0;
}

/**
 * SwafInitPcreOnly
 * - PCRE-only 룰을 초기화하는 함수
 * - JSON 파일 경로를 인자로 받아서 룰을 로드
 *
 * @param json_path: JSON 파일 경로
 * @return: 0 (성공), -1 (실패)
 * @note: 이 함수는 PCRE-only 룰을 초기화하고, 룰을 로드하여 캐시 테이블에 저장
 */
int SwafInitPcreOnly(const char *json_path) {
    json_error_t error;
    json_t *root = json_load_file(json_path, 0, &error);

    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[PCRE-ONLY] JSON 파싱 실패: %s\n", error.text);
        return -1;
    }

    const char *rule_id;
    json_t *rule_obj;

    json_object_foreach(root, rule_id, rule_obj) {
        int is_negated = 0;

        /** 체인 룰 처리 */
        if (json_is_array(rule_obj)) {
            size_t chain_len = json_array_size(rule_obj);
            for (size_t i = 0; i < chain_len; ++i) {
                json_t *step = json_array_get(rule_obj, i);
                const char *regex_raw = json_string_value(json_object_get(step, "regex"));
                if (!regex_raw || strlen(regex_raw) == 0) {
                    fprintf(stderr, "[PCRE-ONLY] 빈 정규식 (체인 %s의 단계 %zu)\n", rule_id, i);
                    continue;
                }

                /** @rx 또는 !@rx 제거 */
                const char *actual_rx = regex_raw;
                if (strncmp(regex_raw, "!@rx", 4) == 0) {
                    is_negated = 1;
                    actual_rx = regex_raw + 4;
                } else if (strncmp(regex_raw, "@rx", 3) == 0) {
                    actual_rx = regex_raw + 3;
                }

                /** 공백 제거 */
                while (*actual_rx == ' ') actual_rx++;
                if (strlen(actual_rx) == 0) {
                    fprintf(stderr, "[PCRE-ONLY] 빈 정규식 (체인 %s의 단계 %zu)\n", rule_id, i);
                    continue;
                }

                /** 정규식 컴파일 */
                int errornum;
                PCRE2_SIZE erroffset;
                pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, \
                                                0, &errornum, &erroffset, NULL);
                if (!re) {
                    PCRE2_UCHAR buffer[256];
                    pcre2_get_error_message(errornum, buffer, sizeof(buffer));
                    fprintf(stderr, "[PCRE-ONLY] 체인 컴파일 실패 (%s_%zu): %s\n", rule_id, i, buffer);
                    continue;
                }

                /** 체인 엔트리 추가 */
                if (PcreCacheTableAddChain(rule_id, i, re, is_negated) != 0) {
                    fprintf(stderr, "[PCRE-ONLY] 체인 엔트리 추가 실패 (%s_%zu)\n", rule_id, i);
                    pcre2_code_free(re);
                    continue;
                }
            }
            continue;
        }

        /** 단일 룰 처리 */
        else if (json_is_object(rule_obj)) {
            const char *regex_raw = json_string_value(json_object_get(rule_obj, "regex"));
            if (!regex_raw || strlen(regex_raw) == 0) continue;

            is_negated = 0;
            const char *actual_rx = regex_raw;
            if (strncmp(regex_raw, "!@rx", 4) == 0) {
                is_negated = 1;
                actual_rx = regex_raw + 4;
            } else if (strncmp(regex_raw, "@rx", 3) == 0) {
                actual_rx = regex_raw + 3;
            }

            /** 공백 제거 */
            while (*actual_rx == ' ') actual_rx++;
            if (strlen(actual_rx) == 0) {
                fprintf(stderr, "[PCRE-ONLY] 빈 정규식 (단일 %s)\n", rule_id);
                continue;
            }

            int errornum;
            PCRE2_SIZE erroffset;
            pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, \
                                            0, &errornum, &erroffset, NULL);

            if (!re) {
                PCRE2_UCHAR buffer[256];
                pcre2_get_error_message(errornum, buffer, sizeof(buffer));
                fprintf(stderr, "[PCRE-ONLY] 컴파일 실패 (%s): %s\n", rule_id, buffer);
                continue;
            }

            if (PcreCacheTableAddToPcreCache(rule_id, re, is_negated) != 0) {
                fprintf(stderr, "[PCRE-ONLY] 캐시 추가 실패: %s\n", rule_id);
                pcre2_code_free(re);
                continue;
            }

            printf("[DEBUG] 단일 룰 로딩 성공: %s (negated=%d)\n", rule_id, is_negated);
        }
    }

    json_decref(root);
    return 0;
}
