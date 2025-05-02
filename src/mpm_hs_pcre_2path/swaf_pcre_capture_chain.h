#ifndef SWAF_PCRE_CAPTURE_CHAIN_H
#define SWAF_PCRE_CAPTURE_CHAIN_H

#include "tx_store.h"

/**
 * SwafCapturePcreChain
 * - 체인 룰 ID에 해당하는 모든 단계(0 ~ MAX_CHAIN_DEPTH-1)에 대해
 * - 매칭을 수행하며, 각 단계의 캡처 결과를 TxStore에 저장
 *
 * @param chain_base_id 예: "942130"
 * @param payload       입력 문자열
 * @param tx            캡처 결과 저장용 구조체
 * @return 1 전체 체인 매칭 및 캡처 성공, 0 실패
 */
int SwafCapturePcreChain(const char *chain_base_id, const char *payload, TxStore *tx);

#endif /* SWAF_PCRE_CAPTURE_CHAIN_H */

