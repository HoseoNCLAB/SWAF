#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define RULES_DIR "/usr/local/swaf/hye/json/parsed_rules"
#define ALL_PARSED_PATH RULES_DIR "/All_parsed_rules.json"

int is_rx_operator(const char *op) {
    if (!op) return 0;
    while (*op == '!' || *op == '@') op++;
    return strcasecmp(op, "rx") == 0;
}

int chain_has_rx(json_t *rule) {
    if (!rule) return 0;
    if (is_rx_operator(json_string_value(json_object_get(rule, "operator"))))
        return 1;
    json_t *chain_arr = json_object_get(rule, "chain");
    if (!chain_arr) return 0;
    size_t i, len = json_array_size(chain_arr);
    for (i = 0; i < len; i++) {
        if (chain_has_rx(json_array_get(chain_arr, i))) return 1;
    }
    return 0;
}

int all_chain_ops_are_rx(json_t *rule) {
    if (!rule) return 0;
    if (!is_rx_operator(json_string_value(json_object_get(rule, "operator"))))
        return 0;
    json_t *chain_arr = json_object_get(rule, "chain");
    if (!chain_arr) return 1;
    size_t i, len = json_array_size(chain_arr);
    for (i = 0; i < len; i++) {
        if (!all_chain_ops_are_rx(json_array_get(chain_arr, i)))
            return 0;
    }
    return 1;
}

json_t* deep_clone_rule(json_t *rule) {
    return json_deep_copy(rule);
}

int main() {
    // 입력 파일 경로
    json_t *rules = json_load_file(ALL_PARSED_PATH, 0, NULL);
    if (!rules) {
        fprintf(stderr, "All_parsed_rules.json 파일을 열 수 없습니다\n");
        return 1;
    }

    json_t *rx_single = json_object();
    json_t *rx_chain = json_object();
    json_t *non_rx_chain = json_object();

    const char *rule_id;
    json_t *rule;
    json_object_foreach(rules, rule_id, rule) {
        json_t *chain = json_object_get(rule, "chain");
        int is_chain = chain && json_array_size(chain) > 0;

        if (!is_chain && is_rx_operator(json_string_value(json_object_get(rule, "operator")))) {
            json_object_set(rx_single, rule_id, rule);
        }
        else if (is_chain && all_chain_ops_are_rx(rule)) {
            json_object_set(rx_chain, rule_id, deep_clone_rule(rule));
        }
        else {
            json_object_set(non_rx_chain, rule_id, rule);
        }

    }

    // 출력 파일 경로
    char rx_single_path[256], rx_chain_path[256], non_rx_chain_path[256];
    snprintf(rx_single_path, sizeof(rx_single_path), RULES_DIR "/rx_single.json");
    snprintf(rx_chain_path, sizeof(rx_chain_path), RULES_DIR "/rx_chain.json");
    snprintf(non_rx_chain_path, sizeof(non_rx_chain_path), RULES_DIR "/non_rx_chain.json");

    if (json_dump_file(rx_single, rx_single_path, JSON_INDENT(2)) < 0)
        fprintf(stderr, "rx_single.json 저장 실패: %s\n", rx_single_path);
    if (json_dump_file(rx_chain, rx_chain_path, JSON_INDENT(2)) < 0)
        fprintf(stderr, "rx_chain.json 저장 실패: %s\n", rx_chain_path);
    if (json_dump_file(non_rx_chain, non_rx_chain_path, JSON_INDENT(2)) < 0)
        fprintf(stderr, "non_rx_chain.json 저장 실패: %s\n", non_rx_chain_path);

    printf("rx_single: %zu개\n", json_object_size(rx_single));
    printf("rx_chain: %zu개\n", json_object_size(rx_chain));
    printf("non_rx_chain: %zu개\n", json_object_size(non_rx_chain));
    printf("총합: %zu개\n", json_object_size(rx_single) + json_object_size(rx_chain) + json_object_size(non_rx_chain));

    json_decref(rx_single);
    json_decref(rx_chain);
    json_decref(non_rx_chain);
    json_decref(rules);
    return 0;
}
