#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_loader.h"
#include "swaf_pcre_cache_table.h"
#include <jansson.h>
#include <pcre2.h>
#include <stdio.h>
#include <string.h>

/* HS-only 룰 초기화 */
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
        pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, 0, &errornum, &erroffset, NULL);

        if (!re) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornum, buffer, sizeof(buffer));
            fprintf(stderr, "[HS-ONLY] 컴파일 실패 (%s): %s\n", rule_id, buffer);
            continue;
        }

        // HsCacheTable에 pcre2_code 직접 추가
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


/* PCRE-only 룰 초기화 */
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
        int is_chain = json_is_array(rule_obj);
        int is_negated = 0;

        if (is_chain) {
            size_t chain_len = json_array_size(rule_obj);
            for (size_t i = 0; i < chain_len; ++i) {
                json_t *step = json_array_get(rule_obj, i);
                const char *regex_raw = json_string_value(json_object_get(step, "regex"));
                if (!regex_raw) continue;

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
                pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, 0, &errornum, &erroffset, NULL);

                if (!re) {
                    PCRE2_UCHAR buffer[256];
                    pcre2_get_error_message(errornum, buffer, sizeof(buffer));
                    fprintf(stderr, "[PCRE-ONLY] 체인 컴파일 실패 (%s_%zu): %s\n", rule_id, i, buffer);
                    continue;
                }

                char chain_id[64];
                snprintf(chain_id, sizeof(chain_id), "%s_%zu", rule_id, i);

                if (PcreCacheTableAddToPcreCache(chain_id, re, is_negated) != 0) {
                    fprintf(stderr, "[PCRE-ONLY] 체인 캐시 추가 실패: %s\n", chain_id);
                    pcre2_code_free(re);
                    continue;
                }

                printf("[DEBUG] 체인 룰 로딩 성공: %s (negated=%d)\n", chain_id, is_negated);
            }
            continue;
        }

        const char *regex_raw = json_string_value(rule_obj);
        if (!regex_raw) continue;

        is_negated = 0;
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
        pcre2_code *re = pcre2_compile((PCRE2_SPTR)actual_rx, PCRE2_ZERO_TERMINATED, 0, &errornum, &erroffset, NULL);

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

        printf("[DEBUG] PCRE-only 룰 로딩 성공: %s (negated=%d)\n", rule_id, is_negated);
    }

    json_decref(root);
    return 0;
}
