#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <dirent.h>
#include <ctype.h>
#include <stdbool.h>

#define CRS_RULE_DIR "../../crs"
#define OUTPUT_JSON_PATH "../../parsed_rules/parsed_crs.json"
#define CHAIN_GROUP_PATH "../../parsed_rules/chain_groups.json"

#define MAX_LINE_LEN 8192
#define MAX_RULE_LEN (MAX_LINE_LEN * 8)
#define MAX_VAL_LEN 2048
#define MAX_KEY_LEN 64
#define MAX_REGEX_LEN 8192

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int count_quotes(const char *s) {
    int count = 0;
    while (*s) {
        if (*s == '"') count++;
        if (*s == '\\' && *(s+1)) s++;
        s++;
    }
    return count;
}

static void extract_field_value(const char *actions, const char *key, char *buf, size_t buflen) {
    const char *p = strstr(actions, key);
    if (!p) {
        buf[0] = '\0';
        return;
    }
    p += strlen(key);
    while (*p == ' ' || *p == ':' || *p == '\'' || *p == '"') p++;
    const char *start = p;
    while (*p && *p != ',' && *p != '\'' && *p != '"') p++;
    size_t len = p - start;
    if (len >= buflen) len = buflen - 1;
    strncpy(buf, start, len);
    buf[len] = '\0';
}

static void extract_multiple_values(const char *actions, const char *key, json_t *array) {
    const char *p = actions;
    while ((p = strstr(p, key)) != NULL) {
        p += strlen(key);
        while (*p == ' ' || *p == ':' || *p == '\'' || *p == '"') p++;
        const char *start = p;
        while (*p && *p != ',' && *p != '\'' && *p != '"') p++;
        size_t len = p - start;
        if (len > 0) {
            char val[MAX_VAL_LEN];
            snprintf(val, sizeof(val), "%.*s", (int)len, start);
            json_array_append_new(array, json_string(trim(val)));
        }
    }
}

static const char *find_closing_quote(const char *start) {
    const char *p = start;
    while (*p) {
        if (*p == '"' && (p == start || *(p - 1) != '\\')) return p;
        p++;
    }
    return NULL;
}

static json_t *parse_sec_rule_block(const char *block, char *id_buf, size_t id_buflen, bool *is_chain) {
    char operator[MAX_KEY_LEN] = "unknown", regex[MAX_REGEX_LEN] = "", actions[MAX_RULE_LEN] = "";

    const char *op = strstr(block, "@");
    if (op) {
        const char *op_end = strpbrk(op, " \t\r\n\"");
        if (op_end) {
            size_t op_len = op_end - op;
            snprintf(operator, sizeof(operator), "%.*s", (int)op_len, op);
            if (operator[0] == '@') memmove(operator, operator + 1, strlen(operator));
        }
    }

    const char *first_quote = strchr(block, '"');
    if (!first_quote) return NULL;
    const char *second_quote = find_closing_quote(first_quote + 1);
    if (!second_quote) return NULL;

    size_t regex_len = second_quote - (first_quote + 1);
    if (regex_len >= MAX_REGEX_LEN) regex_len = MAX_REGEX_LEN - 1;
    strncpy(regex, first_quote + 1, regex_len);
    regex[regex_len] = '\0';

    if (strcmp(operator, "rx") == 0) {
        if (strncmp(regex, "@rx ", 4) == 0)
            memmove(regex, regex + 4, strlen(regex) - 3);
    }

    const char *third_quote = find_closing_quote(second_quote + 1);
    if (!third_quote) return NULL;
    const char *fourth_quote = find_closing_quote(third_quote + 1);
    if (!fourth_quote) return NULL;

    size_t actions_len = fourth_quote - (third_quote + 1);
    if (actions_len >= MAX_RULE_LEN) actions_len = MAX_RULE_LEN - 1;
    strncpy(actions, third_quote + 1, actions_len);
    actions[actions_len] = '\0';

    size_t rlen = strlen(regex);
    if (rlen > 0 && regex[rlen-1] == '\\') regex[rlen-1] = '\0';

    extract_field_value(actions, "id", id_buf, id_buflen);
    *is_chain = strstr(actions, "chain") != NULL;

    json_t *rule = json_object();
    json_object_set_new(rule, "operator", json_string(operator));
    json_object_set_new(rule, "regex", json_string(trim(regex)));
    json_object_set_new(rule, "actions", json_string(actions));

    char buf[MAX_VAL_LEN];
#define SET_FIELD(k, jkey) \
    buf[0] = '\0'; \
    extract_field_value(actions, k, buf, sizeof(buf)); \
    json_object_set_new(rule, jkey, strlen(buf) ? json_string(trim(buf)) : json_string(""));

    SET_FIELD("msg", "msg");
    SET_FIELD("logdata", "logdata");
    SET_FIELD("severity", "severity");
    SET_FIELD("phase", "phase");
    SET_FIELD("ver", "ver");

    json_object_set_new(rule, "capture", json_boolean(strstr(actions, "capture") != NULL));
    json_object_set_new(rule, "block", json_boolean(strstr(actions, "block") != NULL));

    json_t *setvars = json_array();
    extract_multiple_values(actions, "setvar:", setvars);
    json_object_set_new(rule, "setvar", setvars);

    json_t *tags = json_array();
    extract_multiple_values(actions, "tag:", tags);
    json_object_set_new(rule, "tags", tags);

    json_t *transforms = json_array();
    extract_multiple_values(actions, "t:", transforms);
    json_object_set_new(rule, "transformations", transforms);

    return rule;
}

int main() {
    DIR *dir = opendir(CRS_RULE_DIR);
    if (!dir) {
        perror("CRS 디렉토리 열기 실패");
        return 1;
    }

    struct dirent *entry;
    json_t *root = json_object();
    json_t *chain_groups = json_object();
    char filepath[1024];
    char rule_buf[MAX_RULE_LEN] = "";
    bool in_rule = false, last_was_chain = false;
    char current_chain_id[MAX_KEY_LEN] = "";
    json_t *chain_array = NULL;

    while ((entry = readdir(dir)) != NULL) {
        if (!strstr(entry->d_name, ".conf")) continue;
        snprintf(filepath, sizeof(filepath), "%s/%s", CRS_RULE_DIR, entry->d_name);
        FILE *fp = fopen(filepath, "r");
        if (!fp) continue;

        while (fgets(rule_buf, sizeof(rule_buf), fp)) {
            trim(rule_buf);
            if (strncmp(rule_buf, "SecRule", 7) == 0) {
                char full_rule[MAX_RULE_LEN] = "";
                strcat(full_rule, rule_buf);
                int quote_count = count_quotes(full_rule);
                while (quote_count < 4 && fgets(rule_buf, sizeof(rule_buf), fp)) {
                    trim(rule_buf);
                    strcat(full_rule, " ");
                    strcat(full_rule, rule_buf);
                    quote_count = count_quotes(full_rule);
                }

                char id[MAX_KEY_LEN];
                bool is_chain = false;
                json_t *parsed = parse_sec_rule_block(full_rule, id, sizeof(id), &is_chain);
                if (parsed) {
                    if (last_was_chain && chain_array) {
                        json_array_append_new(chain_array, parsed);
                    } else if (is_chain) {
                        chain_array = json_array();
                        json_array_append_new(chain_array, parsed);
                        json_object_set_new(chain_groups, id, json_pack("{s:o}", "rules", chain_array));
                        strncpy(current_chain_id, id, sizeof(current_chain_id));
                    } else {
                        json_object_set_new(root, id, parsed);
                    }
                    last_was_chain = is_chain;
                }
            }
        }
        fclose(fp);
    }
    closedir(dir);

    json_dump_file(root, OUTPUT_JSON_PATH, JSON_INDENT(2));
    json_dump_file(chain_groups, CHAIN_GROUP_PATH, JSON_INDENT(2));
    json_decref(root);
    json_decref(chain_groups);
    printf("[RESULT] 전체 CRS / Chain_Rule 파싱 완료\n");
    return 0;
}
