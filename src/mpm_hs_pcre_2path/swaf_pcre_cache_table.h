#ifndef SWAF_PCRE_CACHE_TABLE_H
#define SWAF_PCRE_CACHE_TABLE_H

#include <stdint.h>
#include <pcre2.h>

/* 해시 함수 시그니처 */
typedef uint32_t (*PcreHashFunc)(const char *key, uint16_t len);

/* 비교 함수 시그니처 */
typedef int (*PcreCompareFunc)(const char *k1, uint16_t l1, const char *k2, uint16_t l2);

/* 해제 함수 시그니처 */
typedef void (*PcreFreeFunc)(void *data);

/* 캐시 엔트리 구조체 */
typedef struct {
    char *rule_id;
    pcre2_code *re;
    int is_negated;
} PcreCacheEntry;

/* 버킷 구조체 */
typedef struct Bucket_ {
    char *key;
    uint16_t key_len;
    void *data;
    struct Bucket_ *next;
} Bucket;

/* PCRE 캐시 테이블 구조체 */
typedef struct PcreCacheTable_ {
    Bucket **buckets;
    uint32_t size;
    PcreHashFunc hash_func;
    PcreCompareFunc cmp_func;
    PcreFreeFunc free_func;
} PcreCacheTable;

/**
 * HS 전용 캐시 테이블 반환
 * @return 전역 HS 전용 캐시 테이블 포인터
 */
PcreCacheTable *HsCacheTableGetGlobal(void);

/**
 * PCRE 전용 캐시 테이블 반환
 * @return 전역 PCRE-only 캐시 테이블 포인터
 */
PcreCacheTable *PcreOnlyCacheTableGetGlobal(void);

/**
 * 새로운 캐시 테이블 생성
 * @param size 해시 테이블 크기
 * @param hash 사용자 정의 해시 함수
 * @param cmp 키 비교 함수
 * @param free_func 해제 함수
 * @return 생성된 테이블 포인터
 */
PcreCacheTable *CreatePcreCacheTable(uint32_t size,
                                     PcreHashFunc hash,
                                     PcreCompareFunc cmp,
                                     PcreFreeFunc free_func);

/* 테이블 초기화 */
int PcreCacheTableInit(void);

/* 테이블 메모리 해제 */
void DestroyPcreCacheTable(PcreCacheTable *table);

/* HS 캐시 테이블에 항목 삽입 */
int PcreCacheTableAddToHsCache(const char *rule_id, pcre2_code *re, int is_negated);

/* PCRE 캐시 테이블에 항목 삽입 */
int PcreCacheTableAddToPcreCache(const char *rule_id, pcre2_code *re, int is_negated);

/* 룰 ID로 컴파일된 정규식 가져오기 */
void *PcreCacheTableLookup(PcreCacheTable *table, const char *key, uint16_t len);

/* 전역 테이블 메모리 해제 */
void PcreCacheTableFree(void);

/* 전역 테이블 항목 디버그 출력 */
void PcreCacheTableDump(PcreCacheTable *table);

/* 캐시 엔트리 해제 */
void FreePcreEntry(void *data);

/* 룰이 부정 조건인지 확인 */
int PcreCacheTableIsNegated(const char *rule_id);

#endif /* SWAF_PCRE_CACHE_TABLE_H */