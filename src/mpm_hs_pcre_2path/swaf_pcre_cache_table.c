#include "swaf_pcre_cache_table.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/** 전역 캐시 테이블 포인터 */
static PcreCacheTable *hs_cache_table = NULL;
static PcreCacheTable *pcre_only_cache_table = NULL;
static PcreCacheTable *chain_cache_table = NULL;


/** 전역 캐시 테이블을 가져옴 */
PcreCacheTable *HsCacheTableGetGlobal(void) {
    return hs_cache_table;
}

PcreCacheTable *PcreOnlyCacheTableGetGlobal(void) {
    return pcre_only_cache_table;
}

PcreCacheTable *ChainCacheTableGetGlobal(void) {
    return chain_cache_table;
}


/**
 * @brief 해시 테이블을 생성하는 함수
 * @param size 해시 테이블의 크기
 * @param hash 해시 함수
 * @param cmp 문자열 비교 함수
 * @param free_func 메모리 해제 함수
 * @return PcreCacheTable* 생성된 캐시 테이블 포인터
 */
PcreCacheTable *CreatePcreCacheTable(uint32_t size,
                                     PcreHashFunc hash,
                                     PcreCompareFunc cmp,
                                     PcreFreeFunc free_func) {
    if (!hash || size == 0)
        return NULL;

    PcreCacheTable *t = (PcreCacheTable *)calloc(1, sizeof(PcreCacheTable));
    if (!t) return NULL;

    t->buckets = (Bucket **)calloc(size, sizeof(Bucket *));
    if (!t->buckets) {
        free(t);
        return NULL;
    }

    t->size = size;
    t->hash_func = hash;
    t->cmp_func = cmp;
    t->free_func = free_func;

    return t;
}


/**
 * @brief 해시 테이블을 해제하는 함수
 * @param t 해제할 캐시 테이블 포인터
 * @note 이 함수는 주어진 캐시 테이블을 해제
 */
void DestroyPcreCacheTable(PcreCacheTable *t) {
    if (!t) return;

    for (uint32_t i = 0; i < t->size; i++) {
        Bucket *b = t->buckets[i];
        while (b) {
            Bucket *next = b->next;
            if (t->free_func) t->free_func(b->data);
            free(b->key);
            free(b);
            b = next;
        }
    }
    free(t->buckets);
    free(t);
}


/**
 * @brief 해시 테이블에 항목을 추가하는 함수
 * @param t 캐시 테이블 포인터
 * @param key 해시 키
 * @param len 해시 키 길이
 * @param data 해시 값 (PCRE 캐시 엔트리)
 * @return int 0: 성공, -1: 실패
 * @note 이 함수는 주어진 키와 값을 사용하여 캐시 테이블에 항목을 추가
 */
int PcreCacheTableInsert(PcreCacheTable *t, const char *key, uint16_t len, void *data) {
    if (!t || !key || len == 0 || !data) return -1;

    uint32_t h = t->hash_func(key, len) % t->size;
    Bucket *b = (Bucket *)calloc(1, sizeof(Bucket));
    if (!b) return -1;

    b->key = strndup(key, len);
    b->key_len = len;
    b->data = data;

    b->next = t->buckets[h];
    t->buckets[h] = b;
    return 0;
}


/**
 * @brief 해시 테이블에서 항목을 조회하는 함수
 * @param t 캐시 테이블 포인터
 * @param key 해시 키
 * @param len 해시 키 길이
 * @return void* 해시 값 (PCRE 캐시 엔트리) 또는 NULL
 * @note 이 함수는 주어진 키를 사용하여 캐시 테이블에서 항목을 조회
 */
void *PcreCacheTableLookup(PcreCacheTable *t, const char *key, uint16_t len) {
    if (!t || !key) return NULL;

    uint32_t h = t->hash_func(key, len) % t->size;
    Bucket *b = t->buckets[h];
    while (b) {
        if (t->cmp_func(b->key, b->key_len, key, len))
            return b->data;
        b = b->next;
    }
    return NULL;
}


/**
 * @brief 해시 테이블의 내용을 덤프하는 함수
 * @param t 캐시 테이블 포인터
 * @note 이 함수는 주어진 캐시 테이블의 내용을 덤프
 */
void PcreCacheTableDump(PcreCacheTable *t) {
    if (!t) return;

    for (uint32_t i = 0; i < t->size; i++) {
        Bucket *b = t->buckets[i];
        while (b) {
            PcreCacheEntry *e = (PcreCacheEntry *)b->data;
            printf("  - %s (negated=%s)\n", e->rule_id, e->is_negated ? "true" : "false");
            b = b->next;
        }
    }
}


/**
 * @brief 해시 함수
 * @param key 해시 키
 * @param len 해시 키 길이
 * @return uint32_t 해시 값
 * @note 이 함수는 주어진 문자열을 해싱하여 해시 값을 생성
 */
static uint32_t PcreHash(const char *key, uint16_t len) {
    const uint8_t *d = (const uint8_t *)key;
    uint32_t h = 0;
    for (uint32_t i = 0; i < len; i++)
        h = h * 31 + d[i];
    return h;
}


/**
 * @brief 문자열 비교 함수
 * @param k1 첫 번째 문자열
 * @param l1 첫 번째 문자열 길이
 * @param k2 두 번째 문자열
 * @param l2 두 번째 문자열 길이
 * @return int 0: 같음, 1: 다름
 * @note 이 함수는 해시 테이블에서 키를 비교하는 데 사용
 */
static int PcreCompare(const char *k1, uint16_t l1, const char *k2, uint16_t l2) {
    return l1 == l2 && strncmp(k1, k2, l1) == 0;
}


/**
 * @brief PCRE 캐시 엔트리 메모리 해제 함수
 * @param data 해제할 데이터 포인터
 * @note 이 함수는 PCRE 캐시 엔트리를 해제
 */
void FreePcreEntry(void *data) {
    PcreCacheEntry *entry = (PcreCacheEntry *)data;
    if (!entry) return;

    if (entry->rule_id) {
        free(entry->rule_id);
        entry->rule_id = NULL;
    }

    if (entry->re) {
        pcre2_code_free(entry->re);
        entry->re = NULL;
    }

    entry->next = NULL;     /** 명시적으로 초기화 */
    free(entry);
}


/**
 * @brief 체인 캐시 테이블에 항목을 추가하는 함수
 * @param rule_id 룰 ID
 * @param step 체인 단계
 * @param re PCRE 정규식
 * @param is_negated 부정 조건 여부
 * @return int 0: 성공, -1: 실패
 * @note 이 함수는 주어진 룰 ID와 PCRE 정규식을 사용하여 체인 캐시 테이블에 항목을 추가
 *       is_negated가 1이면 부정 조건으로 처리
 */
int PcreCacheTableAddChain(const char *rule_id, unsigned long step, pcre2_code *re, int is_negated) {
    if (!rule_id || !re) return -1;

    /** 체인 ID 생성 */
    char chain_id[64];
    snprintf(chain_id, sizeof(chain_id), "%s_%lu", rule_id, step);

    //printf("[DEBUG] rule_id: %s, step: %lu, chain_id: %s\n", rule_id, step, chain_id);

    /** 기존 체인 엔트리 검색 */
    PcreCacheEntry *existing_entry = (PcreCacheEntry *)PcreCacheTableLookup(ChainCacheTableGetGlobal(), rule_id, strlen(rule_id));
    PcreCacheEntry *last_step = existing_entry;

    /** 체인 베이스가 아직 없다면 첫 번째로 추가 */
    if (!existing_entry) {
        /** 첫 번째 체인 단계 생성 */
        PcreCacheEntry *base_entry = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
        if (!base_entry) {
            fprintf(stderr, "[PCRE] 체인 베이스 엔트리 메모리 할당 실패 (%s)\n", rule_id);
            pcre2_code_free(re);
            return -1;
        }

        base_entry->rule_id = strdup(rule_id); 
        base_entry->re = re;
        base_entry->is_negated = is_negated;
        base_entry->next = NULL;

        /** 체인 베이스를 캐시에 추가 */
        if (PcreCacheTableInsert(ChainCacheTableGetGlobal(), rule_id, strlen(rule_id), base_entry) != 0) {
            fprintf(stderr, "[PCRE] 체인 베이스 추가 실패 (%s)\n", rule_id);
            free(base_entry->rule_id);
            free(base_entry);
            pcre2_code_free(re);
            return -1;
        }

        printf("[DEBUG] 체인 베이스 추가 성공: %s (단계=0, negated=%d)\n", rule_id, is_negated);
        return 0;
    }

    /** 기존 체인 엔트리의 마지막 단계로 이동 */
    while (last_step->next != NULL) {
        last_step = last_step->next;
    }

    /** 새로운 체인 단계 생성 */
    PcreCacheEntry *new_step = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
    if (!new_step) {
        fprintf(stderr, "[PCRE] 체인 단계 엔트리 메모리 할당 실패 (%s)\n", chain_id);
        pcre2_code_free(re);
        return -1;
    }

    new_step->rule_id = strdup(chain_id);
    new_step->re = re;
    new_step->is_negated = is_negated;
    new_step->next = NULL;

    /** 기존 체인 엔드에 연결 */
    last_step->next = new_step;
    printf("[DEBUG] 체인 단계 추가 성공: %s (단계=%lu, negated=%d)\n", chain_id, step, is_negated);

    return 0;
}


/**
 * @brief 체인 캐시 엔트리 메모리 해제 함수
 * @param data 해제할 데이터 포인터
 * @note 이 함수는 체인 캐시 엔트리를 해제
 */
void FreePcreChainEntry(void *data) {
    PcreCacheEntry *entry = (PcreCacheEntry *)data;
    while (entry) {
        PcreCacheEntry *next = entry->next;

        if (entry->rule_id) {
            free(entry->rule_id);
            entry->rule_id = NULL;
        }

        if (entry->re) {
            pcre2_code_free(entry->re);
            entry->re = NULL;
        }

        entry->next = NULL;
        free(entry);

        entry = next;
    }
}


/**
 * @brief 글로벌 캐시 테이블 초기화
 * @return int 0: 성공, -1: 실패
 * @note 이 함수는 글로벌 캐시 테이블을 초기화
 */
int PcreCacheTableInit(void) {
    if (hs_cache_table != NULL || pcre_only_cache_table != NULL)
        return 0;

    hs_cache_table = CreatePcreCacheTable(1024, PcreHash, PcreCompare, FreePcreEntry);
    pcre_only_cache_table = CreatePcreCacheTable(1024, PcreHash, PcreCompare, FreePcreEntry);
    chain_cache_table = CreatePcreCacheTable(1024, PcreHash, PcreCompare, FreePcreChainEntry);
    
    if (!hs_cache_table || !pcre_only_cache_table || !chain_cache_table) {
        fprintf(stderr, "[ERROR] 글로벌 캐시 테이블 초기화 실패\n");
        return -1;
    }

    printf("[DEBUG] 글로벌 캐시 테이블 초기화 완료\n");
    return 0;
}


/**
 * @brief 글로벌 캐시 테이블 해제
 * @note 이 함수는 글로벌 캐시 테이블을 해제
 */
void PcreCacheTableFree(void) {
    if (hs_cache_table) DestroyPcreCacheTable(hs_cache_table);
    if (pcre_only_cache_table) DestroyPcreCacheTable(pcre_only_cache_table);
    hs_cache_table = NULL;
    pcre_only_cache_table = NULL;
}


/**
 * @brief PCRE-only 룰 ID가 부정 조건인지 확인하는 함수
 * @param rule_id 룰 ID
 * @return int 1: 부정 조건, 0: 정규식 없음
 * @note 이 함수는 주어진 룰 ID에 대해 부정 조건 여부를 확인    
 */
int PcreCacheTableIsNegated(const char *rule_id) {
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(PcreOnlyCacheTableGetGlobal(), \
                                                                    rule_id, \
                                                                    strlen(rule_id));
    return entry ? entry->is_negated : 0;
}


/**
 * @brief HS-only 캐시 테이블에 항목을 추가하는 함수
 * @param rule_id 룰 ID
 * @param re PCRE 정규식
 * @param is_negated 부정 조건 여부
 * @return int 0: 성공, -1: 실패
 * @note 이 함수는 주어진 룰 ID와 PCRE 정규식을 사용하여 HS-only 캐시 테이블에 항목을 추가
 */
int PcreCacheTableAddToHsCache(const char *rule_id, pcre2_code *re, int is_negated) {
    if (!rule_id || !re) return -1;

    PcreCacheEntry *entry = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
    if (!entry) return -1;

    entry->rule_id = strdup(rule_id);
    entry->re = re;
    entry->is_negated = is_negated;

    return PcreCacheTableInsert(HsCacheTableGetGlobal(), rule_id, strlen(rule_id), entry);
}


/**
 * @brief HS-only 캐시 테이블에 항목을 추가하는 함수
 * @param rule_id 룰 ID
 * @param re PCRE 정규식
 * @param is_negated 부정 조건 여부
 * @return int 0: 성공, -1: 실패
 * @note 이 함수는 주어진 룰 ID와 PCRE 정규식을 사용하여 HS-only 캐시 테이블에 항목을 추가
 */
int PcreCacheTableAddToPcreCache(const char *rule_id, pcre2_code *re, int is_negated) {
    if (!rule_id || !re) return -1;

    PcreCacheEntry *entry = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
    if (!entry) return -1;

    entry->rule_id = strdup(rule_id);
    entry->re = re;
    entry->is_negated = is_negated;
    
    /** 단일 룰이므로 next를 명시적으로 NULL로 설정 */
    entry->next = NULL;

    printf("[DEBUG] 단일 룰 캐시에 추가: %s (negated=%d, next=%p)\n", rule_id, is_negated, entry->next);

    return PcreCacheTableInsert(PcreOnlyCacheTableGetGlobal(), rule_id, strlen(rule_id), entry);
}