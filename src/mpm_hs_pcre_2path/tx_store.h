#ifndef __TX_STORE_H__
#define __TX_STORE_H__

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_CAPTURE_GROUPS 10     // PCRE 최대 캡처 그룹 수
#define MAX_CAPTURE_LEN    1024   // 각 캡처 그룹 문자열 최대 길이

/**
 * TX 변수 저장 구조체
 * TX.0 ~ TX.9 에 해당하는 포인터 배열
 */
typedef struct {
    char *tx[MAX_CAPTURE_GROUPS];
} TxStore;

/**
 * TX 변수 초기화
 */
static inline void InitTxStore(TxStore *tx) {
    if (!tx) return;
    for (int i = 0; i < MAX_CAPTURE_GROUPS; ++i) {
        tx->tx[i] = NULL;
    }
}

/**
 * TX 변수 전체 해제
 */
static inline void FreeTxStore(TxStore *tx) {
    if (!tx) return;
    for (int i = 0; i < MAX_CAPTURE_GROUPS; ++i) {
        if (tx->tx[i]) {
            free(tx->tx[i]);
            tx->tx[i] = NULL;
        }
    }
}

/**
 * TX 변수 출력 (디버깅용)
 */
static inline void PrintTxStore(const TxStore *tx) {
    if (!tx) return;
    for (int i = 0; i < MAX_CAPTURE_GROUPS; ++i) {
        if (tx->tx[i]) {
            printf("[DEBUG] TX.%d = %s (주소: %p)\n", i, tx->tx[i], (void *)tx->tx[i]);
        } else {
            printf("[DEBUG] TX.%d = (null)\n", i);
        }
    }
}

#endif /* __TX_STORE_H__ */
