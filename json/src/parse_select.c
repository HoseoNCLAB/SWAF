#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define RULES_DIR "/usr/local/swaf/hye/json/parsed_rules"
#define ALL_PARSED_PATH RULES_DIR "/All_parsed_rules.json"

int main() {
    // 파일 불러오기
    json_t *rules = json_load_file(ALL_PARSED_PATH, 0, NULL);
    if (!rules) {
        fprintf(stderr, "All_parsed_rules.json 파일을 열 수 없습니다\n");
        return 1;
    }

    json_t *basic_rule = json_object();
    json_t *chain_rule = json_object();

    const char *rule_id;
    json_t *rule;
    json_object_foreach(rules, rule_id, rule) {
        json_t *chain = json_object_get(rule, "chain");
        // chain이 있고, 배열 크기가 0 초과면 chain_rule에!
        if (chain && json_array_size(chain) > 0) {
            json_object_set(chain_rule, rule_id, rule);
        }
        // chain이 없거나, chain 배열이 비었으면 basic_rule에!
        else {
            json_object_set(basic_rule, rule_id, rule);
        }
    }

    // 파일 경로 지정
    char basic_path[256], chain_path[256];
    snprintf(basic_path, sizeof(basic_path), RULES_DIR "/basic_rule.json");
    snprintf(chain_path, sizeof(chain_path), RULES_DIR "/chain_rule.json");

    // 파일 저장
    if (json_dump_file(basic_rule, basic_path, JSON_INDENT(2)) < 0)
        fprintf(stderr, "basic_rule.json 저장 실패: %s\n", basic_path);
    if (json_dump_file(chain_rule, chain_path, JSON_INDENT(2)) < 0)
        fprintf(stderr, "chain_rule.json 저장 실패: %s\n", chain_path);

    printf("basic_rule: %zu개\n", json_object_size(basic_rule));
    printf("chain_rule: %zu개\n", json_object_size(chain_rule));
    printf("총합: %zu개\n", json_object_size(basic_rule) + json_object_size(chain_rule));

    json_decref(basic_rule);
    json_decref(chain_rule);
    json_decref(rules);
    return 0;
}
