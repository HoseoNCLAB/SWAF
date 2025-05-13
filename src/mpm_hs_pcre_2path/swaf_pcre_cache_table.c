#include "swaf_pcre_cache_table.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* 전역 캐시 테이블 포인터 */
static PcreCacheTable *hs_cache_table = NULL;
static PcreCacheTable *pcre_only_cache_table = NULL;

/* 전역 캐시 테이블을 가져옴 */
PcreCacheTable *HsCacheTableGetGlobal(void) {
    return hs_cache_table;
}

PcreCacheTable *PcreOnlyCacheTableGetGlobal(void) {
    return pcre_only_cache_table;
}

/* 해시 테이블 생성 */
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

/* 해시 테이블 제거 */
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

/* 해시 테이블에 새로운 항목 추가 */
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

/* 키를 기준으로 해시 테이블에서 항목 조회 */
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

/* 모든 항목을 출력 (디버그 용도) */
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

/* 문자열 기반 해시 함수 (31 해싱) */
static uint32_t PcreHash(const char *key, uint16_t len) {
    const uint8_t *d = (const uint8_t *)key;
    uint32_t h = 0;
    for (uint32_t i = 0; i < len; i++)
        h = h * 31 + d[i];
    return h;
}

/* 문자열 기반 키 비교 함수 */
static int PcreCompare(const char *k1, uint16_t l1, const char *k2, uint16_t l2) {
    return l1 == l2 && strncmp(k1, k2, l1) == 0;
}

/* PcreCacheEntry 메모리 해제 */
void FreePcreEntry(void *data) {
    PcreCacheEntry *entry = (PcreCacheEntry *)data;
    if (entry) {
        free(entry->rule_id);
        if (entry->re) pcre2_code_free(entry->re);
        free(entry);
    }
}

/* 글로벌 캐시 테이블 초기화 */
int PcreCacheTableInit(void) {
    if (hs_cache_table != NULL || pcre_only_cache_table != NULL)
        return 0;

    hs_cache_table = CreatePcreCacheTable(1024, PcreHash, PcreCompare, FreePcreEntry);
    pcre_only_cache_table = CreatePcreCacheTable(1024, PcreHash, PcreCompare, FreePcreEntry);
    return (hs_cache_table == NULL || pcre_only_cache_table == NULL) ? -1 : 0;
}

/* 글로벌 테이블 해제 */
void PcreCacheTableFree(void) {
    if (hs_cache_table) DestroyPcreCacheTable(hs_cache_table);
    if (pcre_only_cache_table) DestroyPcreCacheTable(pcre_only_cache_table);
    hs_cache_table = NULL;
    pcre_only_cache_table = NULL;
}

/* 룰 ID가 부정 조건인지 확인 */
int PcreCacheTableIsNegated(const char *rule_id) {
    PcreCacheEntry *entry = (PcreCacheEntry *)PcreCacheTableLookup(PcreOnlyCacheTableGetGlobal(), rule_id, strlen(rule_id));
    return entry ? entry->is_negated : 0;
}

/* 룰 ID와 컴파일된 정규식을 HS-only 캐시에 추가 */
int PcreCacheTableAddToHsCache(const char *rule_id, pcre2_code *re, int is_negated) {
    if (!rule_id || !re) return -1;

    PcreCacheEntry *entry = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
    if (!entry) return -1;

    entry->rule_id = strdup(rule_id);
    entry->re = re;
    entry->is_negated = is_negated;

    return PcreCacheTableInsert(HsCacheTableGetGlobal(), rule_id, strlen(rule_id), entry);
}

/* 룰 ID와 컴파일된 정규식을 PCRE-only 캐시에 추가 */
int PcreCacheTableAddToPcreCache(const char *rule_id, pcre2_code *re, int is_negated) {
    if (!rule_id || !re) return -1;

    PcreCacheEntry *entry = (PcreCacheEntry *)malloc(sizeof(PcreCacheEntry));
    if (!entry) return -1;

    entry->rule_id = strdup(rule_id);
    entry->re = re;
    entry->is_negated = is_negated;

    return PcreCacheTableInsert(PcreOnlyCacheTableGetGlobal(), rule_id, strlen(rule_id), entry);
}