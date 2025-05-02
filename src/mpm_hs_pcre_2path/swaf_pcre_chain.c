#define PCRE2_CODE_UNIT_WIDTH 8

#include "swaf_pcre_chain.h"
#include "swaf_pcre_matcher.h"

#include <jansson.h>
#include <stdio.h>
#include <string.h>

#define PCRE_CHAIN_JSON_PATH "../../parsed_rules/pcre_only_rules.json"

int SwafMatchPcreChain(const char *rule_id, const char *payload) {
    json_error_t error;
    json_t *root = json_load_file(PCRE_CHAIN_JSON_PATH, 0, &error);
    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[CHAIN] JSON 파싱 실패: %s\n", error.text);
        return 0;
    }

    json_t *chain_array = json_object_get(root, rule_id);
    if (!chain_array || !json_is_array(chain_array)) {
        fprintf(stderr, "[CHAIN] 룰 ID '%s'에 해당하는 체인 룰 없음\n", rule_id);
        json_decref(root);
        return 0;
    }

    size_t len = json_array_size(chain_array);
    for (size_t i = 0; i < len; ++i) {
        json_t *step = json_array_get(chain_array, i);
        const char *regex = json_string_value(json_object_get(step, "regex"));
        if (!regex) continue;

        // chain 룰은 전처리에서 각 단계마다 고유 ID를 붙였다고 가정
        char sub_id[64];
        snprintf(sub_id, sizeof(sub_id), "%s_%zu", rule_id, i);

        if (!SwafMatchPcre(sub_id, payload)) {
            json_decref(root);
            return 0; // 하나라도 실패하면 전체 실패
        }
    }

    json_decref(root);
    return 1; // 모두 매칭 성공
}

