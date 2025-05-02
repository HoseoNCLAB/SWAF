#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <hs.h>

#define INPUT_JSON_PATH "../../parsed_rules/parsed_crs.json"
#define HS_OUTPUT_JSON "../../parsed_rules/hyperscan_only_rules.json"
#define PCRE_OUTPUT_JSON "../../parsed_rules/pcre_only_rules.json"
#define NON_RX_OUTPUT_JSON "../../parsed_rules/non_rx_rules.json"
#define CHAIN_GROUPS_JSON "../../parsed_rules/chain_groups.json"

// Hyperscan 컴파일 가능 여부 확인
static int is_hyperscan_compatible(const char *pattern) {
    if (pattern == NULL) return 0;
    if (strlen(pattern) > 4096) return 0;

    hs_database_t *db = NULL;
    hs_compile_error_t *err = NULL;

    int ret = hs_compile(
        pattern,
        HS_FLAG_DOTALL | HS_FLAG_MULTILINE,
        HS_MODE_BLOCK,
        NULL,
        &db,
        &err
    );

    if (ret != HS_SUCCESS) {
        if (err) hs_free_compile_error(err);
        return 0;
    }

    hs_free_database(db);
    return 1;
}

static int is_all_rx(json_t *rule_array) {
    size_t i;
    json_t *subrule;
    if (!json_is_array(rule_array)) return 0;
    json_array_foreach(rule_array, i, subrule) {
        const char *op = json_string_value(json_object_get(subrule, "operator"));
        if (!op || strcmp(op, "rx") != 0) return 0;
    }
    return 1;
}

static int is_all_hs_compatible(json_t *rule_array) {
    size_t i;
    json_t *subrule;
    if (!json_is_array(rule_array)) return 0;
    json_array_foreach(rule_array, i, subrule) {
        const char *re = json_string_value(json_object_get(subrule, "regex"));
        if (!is_hyperscan_compatible(re)) return 0;
    }
    return 1;
}

static json_t *load_chain_rules(const char *filepath) {
    json_error_t error;
    json_t *chain_root = json_load_file(filepath, 0, &error);
    if (!chain_root || !json_is_object(chain_root)) {
        fprintf(stderr, "[!] Chain JSON 로드 실패: %s\n", error.text);
        return NULL;
    }
    return chain_root;
}

int main() {
    json_error_t error;
    json_t *root = json_load_file(INPUT_JSON_PATH, 0, &error);
    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[!] JSON 파일 로드 실패: %s\n", error.text);
        return 1;
    }

    json_t *chain_root = load_chain_rules(CHAIN_GROUPS_JSON);
    if (!chain_root) {
        fprintf(stderr, "[!] 체인룰 JSON 로드 실패. 계속 진행합니다.\n");
        chain_root = json_object();
    }

    json_t *hs_rules = json_object();
    json_t *pcre_rules = json_object();
    json_t *non_rx_rules = json_object();

    const char *key;
    json_t *entry;
    int hs_count = 0, pcre_count = 0, non_rx_count = 0;

    json_object_foreach(root, key, entry) {
        if (json_is_array(entry)) {
            // parsed_crs.json에는 없어야 함
            continue;
        }
        const char *op = json_string_value(json_object_get(entry, "operator"));
        const char *re = json_string_value(json_object_get(entry, "regex"));

        if (!op || strcmp(op, "rx") != 0) {
            json_object_set(non_rx_rules, key, entry);
            non_rx_count++;
        } else if (is_hyperscan_compatible(re)) {
            json_object_set(hs_rules, key, entry);
            hs_count++;
        } else {
            json_object_set(pcre_rules, key, entry);
            pcre_count++;
        }
    }

    // 체인룰 처리
    json_object_foreach(chain_root, key, entry) {
        if (!is_all_rx(json_object_get(entry, "rules"))) {
            json_object_set(non_rx_rules, key, json_object_get(entry, "rules"));
            non_rx_count++;
        } else {
            json_object_set(pcre_rules, key, json_object_get(entry, "rules"));
            pcre_count++;
        }
    }

    json_dump_file(hs_rules, HS_OUTPUT_JSON, JSON_INDENT(2));
    json_dump_file(pcre_rules, PCRE_OUTPUT_JSON, JSON_INDENT(2));
    json_dump_file(non_rx_rules, NON_RX_OUTPUT_JSON, JSON_INDENT(2));

    printf("[+] Hyperscan-only 룰 저장 완료: %s (%d개)\n", HS_OUTPUT_JSON, hs_count);
    printf("[+] PCRE-only 룰 저장 완료: %s (%d개)\n", PCRE_OUTPUT_JSON, pcre_count);
    printf("[+] Non-RX 룰 저장 완료: %s (%d개)\n", NON_RX_OUTPUT_JSON, non_rx_count);

    json_decref(root);
    json_decref(chain_root);
    json_decref(hs_rules);
    json_decref(pcre_rules);
    json_decref(non_rx_rules);
    return 0;
}
