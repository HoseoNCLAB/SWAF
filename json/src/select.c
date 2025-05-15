#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define OUTDIR "/usr/local/swaf/hye/json/parsed_rules"

void strip_op_prefix(const char *orig, char *out, size_t outlen) {
    // @, !, @!, !@ 모두 제거
    while (*orig == '@' || *orig == '!') orig++;
    strncpy(out, orig, outlen - 1);
    out[outlen - 1] = '\0';
}

int main() {
    json_t *rules = json_load_file("All_parsed_rules.json", 0, NULL);
    if (!rules) {
        fprintf(stderr, "All_parsed_rules.json 파일을 열 수 없습니다\n");
        return 1;
    }

    // 오퍼레이터별 그룹핑
    json_t *op_groups = json_object();
    const char *rule_id;
    json_t *rule;

    json_object_foreach(rules, rule_id, rule) {
        const char *op = json_string_value(json_object_get(rule, "operator"));
        if (!op) continue;
        char norm_op[64];
        strip_op_prefix(op, norm_op, sizeof(norm_op));

        json_t *group = json_object_get(op_groups, norm_op);
        if (!group) {
            group = json_object();
            json_object_set_new(op_groups, norm_op, group);
        }
        // ID로 그룹에 추가
        json_object_set(group, rule_id, rule);
    }

    // 오퍼레이터별 파일로 저장 + 개수 카운트
    const char *op_name;
    json_t *group_obj;
    size_t total = 0;

    printf("----- 오퍼레이터별 파싱 개수 -----\n");

    json_object_foreach(op_groups, op_name, group_obj) {
        size_t cnt = json_object_size(group_obj);
        printf("%s: %zu개\n", op_name, cnt);

        // 파일로 저장
        char filename[512];
        snprintf(filename, sizeof(filename), OUTDIR "/%s.json", op_name);
        if (json_dump_file(group_obj, filename, JSON_INDENT(2)) < 0) {
            fprintf(stderr, "파일 저장 실패: %s\n", filename);
        }
        total += cnt;
    }
    printf("-------------------------------\n");
    printf("오퍼레이터별 룰 총합: %zu개\n", total);

    json_decref(op_groups);
    json_decref(rules);
    return 0;
}
