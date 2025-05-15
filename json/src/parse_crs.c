#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <jansson.h>

#define CRSDIR "/usr/local/swaf/hye/json/crs"
#define MAX_LINE 8192

static char *pending_chain_id = NULL;

static char *trim(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
    return s;
}

static char *remove_backslashes(const char *s) {
    char *dst = malloc(strlen(s) + 1);
    char *p = dst;
    while (*s) {
        if (*s != '\\') *p++ = *s;
        s++;
    }
    *p = '\0';
    return dst;
}

void process_rule(char *buf, json_t *rules_obj) {
    // Extract operator and regex
    char *op_start = strchr(buf, '"'); if (!op_start) return;
    char *op_end = strchr(op_start + 1, '"'); if (!op_end) return;
    char *op_regex = strndup(op_start + 1, op_end - op_start - 1);
    char *space = strchr(op_regex, ' ');
    char *operator_name, *regex_str;
    if (space) {
        operator_name = strndup(op_regex, space - op_regex);
        regex_str = strdup(space + 1);
    } else {
        operator_name = strdup(op_regex);
        regex_str = strdup("");
    }
    free(op_regex);

        // Extract actions (allow missing actions for simple chain rules)
    char *actions = strdup("");
    char *act_start = strchr(op_end + 1, '"');
    if (act_start) {
        char *act_end = strrchr(buf, '"');
        if (act_end && act_end > act_start) {
            char *actions_raw = strndup(act_start + 1, act_end - act_start - 1);
            free(actions);
            actions = remove_backslashes(actions_raw);
            free(actions_raw);
        }
    }
    // if no action quotes, actions remains empty string

    // Determine ID (top-level or chain target)
    char id_buf[64];
    if (pending_chain_id) {
        strcpy(id_buf, pending_chain_id);
    } else {
        char *id_tok = strstr(actions, "id:");
        if (!id_tok) { free(operator_name); free(regex_str); free(actions); return; }
        id_tok += 3;
        sscanf(id_tok, "%63[^, ]", id_buf);
    }

    // Parse flags
    int block = !!(strstr(actions, "deny") || strstr(actions, "block"));
    int has_chain = !!strstr(actions, "chain");

    // Create JSON object for this rule
    json_t *rule_json = json_object();
    // If top-level, register under its ID
    if (!pending_chain_id) {
        json_object_set_new(rules_obj, id_buf, rule_json);
    }

    // Populate common fields
    json_object_set_new(rule_json, "operator", json_string(operator_name));
    json_object_set_new(rule_json, "regex", json_string(regex_str));
    json_object_set_new(rule_json, "actions", json_string(actions));
    json_object_set_new(rule_json, "msg", json_string(""));
    json_object_set_new(rule_json, "logdata", json_string(""));
    json_object_set_new(rule_json, "severity", json_string(""));
    json_object_set_new(rule_json, "phase", json_string(""));
    json_object_set_new(rule_json, "ver", json_string(""));
    json_object_set_new(rule_json, "capture", json_true());
    json_object_set_new(rule_json, "block", json_boolean(block));
    json_object_set_new(rule_json, "setvar", json_array());
    json_object_set_new(rule_json, "tags", json_array());
    json_object_set_new(rule_json, "transformations", json_array());

    // Parse detailed tokens
    char *saveptr;
    char *tok = strtok_r(actions, ",", &saveptr);
    while (tok) {
        tok = trim(tok);
        if (strcmp(tok, "no-capture") == 0) {
            json_object_set(rule_json, "capture", json_false());
        } else if (strncmp(tok, "msg:", 4) == 0) {
            char *p = strchr(tok+4, '\''); char *q = strrchr(tok+4, '\'');
            if (p && q && q>p) { *q='\0'; json_object_set_new(rule_json, "msg", json_string(p+1)); }
        } else if (strncmp(tok, "logdata:", 8) == 0) {
            char *p = strchr(tok+8, '\''); char *q = strrchr(tok+8, '\'');
            if (p && q && q>p) { *q='\0'; json_object_set_new(rule_json, "logdata", json_string(p+1)); }
        } else if (strncmp(tok, "severity:", 9) == 0) {
            char *p = strchr(tok+9, '\''); char *q = strrchr(tok+9, '\'');
            if (p && q && q>p) { *q='\0'; json_object_set_new(rule_json, "severity", json_string(p+1)); }
        } else if (strncmp(tok, "phase:", 6) == 0) {
            json_object_set_new(rule_json, "phase", json_string(tok+6));
        } else if (strncmp(tok, "ver:", 4) == 0) {
            char *p = strchr(tok+4, '\''); char *q = strrchr(tok+4, '\'');
            if (p && q && q>p) { *q='\0'; json_object_set_new(rule_json, "ver", json_string(p+1)); }
        } else if (strncmp(tok, "tag:", 4) == 0) {
            char *p = strchr(tok+4, '\''); char *q = strrchr(tok+4, '\'');
            if (p && q && q>p) { *q='\0'; json_array_append_new(json_object_get(rule_json, "tags"), json_string(p+1)); }
        } else if (strncmp(tok, "setvar:", 7) == 0) {
            json_array_append_new(json_object_get(rule_json, "setvar"), json_string(tok+7));
        } else if (strncmp(tok, "t:", 2) == 0) {
            json_array_append_new(json_object_get(rule_json, "transformations"), json_string(tok+2));
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    // Finally, handle chain: append or initialize as last step
    if (pending_chain_id) {
        // Sub-rule: append to parent chain
        json_t *parent = json_object_get(rules_obj, pending_chain_id);
        json_t *chain_arr = json_object_get(parent, "chain");
        json_array_append_new(chain_arr, rule_json);
    } else {
        // Top-level: ensure empty chain array at end
        json_object_set_new(rule_json, "chain", json_array());
    }

    // Manage pending_chain_id lifecycle
    if (!pending_chain_id && has_chain) {
        pending_chain_id = strdup(id_buf);
    } else if (pending_chain_id && !has_chain) {
        free(pending_chain_id);
        pending_chain_id = NULL;
    }

    free(operator_name);
    free(regex_str);
    free(actions);
}

void parse_directory(const char *path, json_t *rules_obj) {
    struct stat st;
    if (stat(path, &st) < 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *ent;
        while (d && (ent = readdir(d)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
            char sub[PATH_MAX]; snprintf(sub, sizeof(sub), "%s/%s", path, ent->d_name);
            parse_directory(sub, rules_obj);
        }
        if (d) closedir(d);
    } else if (strstr(path, ".conf")) {
        FILE *f = fopen(path, "r"); char *line=NULL; size_t len=0;
        char *buf=NULL; size_t buf_len=0; int in_rule=0;
        while (f && getline(&line, &len, f) != -1) {
            char *t = trim(line);
            if (!strncmp(t, "SecRule", 7)) {
                if (in_rule) { process_rule(buf, rules_obj); free(buf); }
                in_rule = 1; buf_len = strlen(t)+2; buf=malloc(buf_len); strcpy(buf,t);
            } else if (in_rule) {
                buf_len += strlen(t)+2; buf=realloc(buf,buf_len); strcat(buf,t);
                if (!strlen(t) || t[strlen(t)-1] != '\\') {
                    process_rule(buf, rules_obj); free(buf); buf=NULL; in_rule=0;
                }
            }
        }
        if (line) free(line); if (f) fclose(f);
    }
}


int main(int argc, char *argv[]) {
    const char *crs_path = (argc >= 2) ? argv[1] : CRSDIR;
    json_t *rules = json_object();

    parse_directory(crs_path, rules);

    // 파싱된 룰 수 계산
    size_t rule_count = json_object_size(rules);

    // JSON 파일로 출력
    if (json_dump_file(rules, "All_parsed_rules.json", JSON_INDENT(2)) < 0) {
        fprintf(stderr, "json_dump_file failed\n");
        json_decref(rules);
        return 1;
    }

    // 파싱된 룰 개수 출력
    printf("총 %zu개의 룰을 파싱했습니다.\n", rule_count); //586개 파싱됨

    json_decref(rules);
    return 0;
}

