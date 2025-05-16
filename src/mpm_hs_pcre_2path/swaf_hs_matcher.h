#ifndef __SWAF_HS_MATCHER_H__
#define __SWAF_HS_MATCHER_H__

#include <stdint.h>

#define MAX_PAYLOAD_LEN 8192

/**
 * SigMatchResult
 * - Hyperscan 매칭 결과 구조체
 */
typedef struct {
    int match_cnt;              /** 매칭된 룰 개수 */
    uint32_t rule_ids[128];     /** 매칭된 룰 ID 배열 */
} SigMatchResult;

SigMatchResult SwafMatchHyperscan(const char *payload);

#endif

