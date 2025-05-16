#include "swaf_hs_loader.h"
#include "mpm_hs.h"
#include "mpm_hs_core.h"
#include "mpm.h"
#include "mem.h"
#include "sig_id.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

MpmCtx mpm_ctx;

/**
 * SwafInitHyperscan
 * - Hyperscan 룰 초기화 함수
 * - JSON 파일을 로드하여 Hyperscan 룰을 초기화
 *
 * @param json_path: JSON 파일 경로
 * @return: 0 (성공), -1 (실패)
 * @note: 이 함수는 JSON 파일을 로드하고, Hyperscan 룰을 초기화하여 등록
 * @note: 등록된 룰은 Hyperscan DB에 컴파일됨
 */
int SwafInitHyperscan(const char *json_path) {
    json_error_t error;
    json_t *root = json_load_file(json_path, 0, &error);
    if (!root || !json_is_object(root)) {
        fprintf(stderr, "[HS] JSON 로드 실패: %s\n", error.text);
        return -1;
    }

    SCHSInitCtx(&mpm_ctx);
    MpmConfig mpm_conf;
    memset(&mpm_conf, 0, sizeof(mpm_conf));

    const char *rule_id;
    json_t *rule_obj;
    int pattern_count = 0;

    json_object_foreach(root, rule_id, rule_obj) {
        const char *regex_raw = json_string_value(json_object_get(rule_obj, "regex"));
        if (!regex_raw) {
            fprintf(stderr, "[HS] rule %s 에서 regex 누락됨\n", rule_id);
            continue;
        }

        /** 디버그용 */
        // printf("[DEBUG] Hyperscan 등록 예정 정규식((?i) 제거 전): %s\n", regex_raw);

        uint32_t flags = HS_FLAG_DOTALL | HS_FLAG_MULTILINE;
        bool is_ci = false;

        if (strncmp(regex_raw, "(?i)", 4) == 0) {
            regex_raw += 4;
            flags |= HS_FLAG_CASELESS;
            is_ci = true;
        }

        /** 디버그용 */
        // printf("[DEBUG] Hyperscan 등록 예정 정규식((?i) 제거 후): %s\n", regex_raw);

        uint32_t sid = (uint32_t)atoi(rule_id);
        uint32_t pid = sid;
        uint16_t offset = 0;
        uint16_t depth = MAX_PAYLOAD_LEN;

        int r;
        if (is_ci) {
            r = SCHSAddPatternCI(&mpm_ctx, (uint8_t *)regex_raw, (uint16_t)strlen(regex_raw),
                                 offset, depth, pid, sid, flags);
        } else {
            r = SCHSAddPatternCS(&mpm_ctx, (uint8_t *)regex_raw, (uint16_t)strlen(regex_raw),
                                 offset, depth, pid, sid, flags);
        }

        if (r != 0) {
            fprintf(stderr, "[HS] 패턴 추가 실패: SID %s (%s)\n", rule_id, regex_raw);
            continue;
        }

        printf("[REGISTER] SID %u → %s | flags: 0x%x\n", sid, regex_raw, flags);
        pattern_count++;
    }

    printf("[INFO] 등록된 정규식 총 개수: %d\n", pattern_count);

    if (SCHSPreparePatterns(&mpm_conf, &mpm_ctx) != 0) {
        fprintf(stderr, "[HS] Hyperscan DB 컴파일 실패\n");
        return -1;
    }

    printf("[HS] Hyperscan DB 컴파일 완료\n");
    json_decref(root);
    return 0;
}


/**
 * SwafConnectPatternSids
 * - Hyperscan 룰과 SID 연결 함수
 * - Hyperscan 룰에 대해 SID를 설정
 *
 * @return: 0 (성공), -1 (실패)
 * @note: 이 함수는 Hyperscan 룰에 대해 SID를 설정하여 룰을 연결
 */
int SwafConnectPatternSids(void) {
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx.ctx;
    if (ctx == NULL || ctx->pattern_db == NULL) {
        fprintf(stderr, "[HS] PatternDatabase NULL\n");
        return -1;
    }

    PatternDatabase *pd = ctx->pattern_db;

    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        SCHSPattern *p = pd->parray[i];
        if (p == NULL)
            continue;

        if (p->sids) {
            SCFree(p->sids);
            p->sids = NULL;
            p->sids_size = 0;
        }

        SigIntId *sid_arr = SCCalloc(1, sizeof(SigIntId), SigIntId);
        if (!sid_arr) {
            fprintf(stderr, "[HS] SID 메모리 할당 실패 (pattern %u)\n", i);
            return -1;
        }

        sid_arr[0] = p->id;
        p->sids = sid_arr;
        p->sids_size = 1;

        /** 디버그용 */
        // printf("[CONNECT] Pattern %u (id=%u) → SID 설정 완료: %u\n", i, p->id, sid_arr[0]);
    }

    return 0;
}
