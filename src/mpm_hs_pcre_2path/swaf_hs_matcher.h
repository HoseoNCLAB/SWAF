#ifndef __SWAF_HS_MATCHER_H__
#define __SWAF_HS_MATCHER_H__

#include <stdint.h>

#define MAX_PAYLOAD_LEN 8192

typedef struct {
    int match_cnt;
    uint32_t rule_ids[128]; // 매칭된 룰 ID 최대 128개
} SigMatchResult;

SigMatchResult SwafMatchHyperscan(const char *payload);

#endif

