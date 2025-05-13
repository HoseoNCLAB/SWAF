#ifndef __SWAF_PCRE_MATCHER_H__
#define __SWAF_PCRE_MATCHER_H__

#include <stdint.h>
#include "tx_store.h"
/**
 * 주어진 rule_id에 해당하는 PCRE 정규식으로 subject 문자열이 매칭되는지 검사
 * @param rule_id JSON에서 컴파일한 룰 ID (문자열)
 * @param subject 페이로드 또는 검사할 입력 문자열
 * @return 1 (매칭됨), 0 (매칭 안됨)
 */
int SwafMatchPcre(const char *rule_id, const char *subject);

/**
 * 주어진 체인 룰 ID에 해당하는 PCRE 정규식으로 subject 문자열이 매칭되는지 검사
 * @param chain_base_id JSON에서 컴파일한 체인 룰 ID (문자열)
 * @param payload 페이로드 또는 검사할 입력 문자열
 * @return 1 (매칭됨), 0 (매칭 안됨)
 */
int SwafMatchPcreChain(const char *chain_base_id, const char *payload);

/**
 * 주어진 룰 ID에 대해 PCRE 매칭을 수행하고, 매칭 결과를 반환
 * @param subject 입력 문자열
 * @param len 입력 문자열 길이
 * @param rule_id 룰 ID
 * @param tx 캡처 결과를 저장할 TxStore 구조체
 * @return 1 (매칭됨), 0 (매칭 안됨)
 */
int SwafPcreMatchWithId(const char *subject, int len, uint32_t rule_id, TxStore *tx);

#endif /* __SWAF_PCRE_MATCHER_H__ */