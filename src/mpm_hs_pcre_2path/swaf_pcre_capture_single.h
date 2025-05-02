#ifndef __SWAF_PCRE_CAPTURE_H__
#define __SWAF_PCRE_CAPTURE_H__

#include "tx_store.h"

/**
 * rule_id에 해당하는 정규식으로 subject를 매칭하고,
 * 캡처 그룹 결과를 TX 저장소에 복사함.
 *
 * @return 1 (캡처 성공), 0 (실패 또는 매칭 안됨)
 */
int SwafCapturePcre(const char *rule_id, const char *subject, TxStore *tx);

#endif /* __SWAF_PCRE_CAPTURE_H__ */
