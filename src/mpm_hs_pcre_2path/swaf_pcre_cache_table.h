#ifndef SWAF_PCRE_CACHE_TABLE_H
#define SWAF_PCRE_CACHE_TABLE_H

#include <stdint.h>
#include <pcre2.h>

/** 해시 함수 시그니처 */
typedef uint32_t (*PcreHashFunc)(const char *key, uint16_t len);


/** 문자열 비교 함수 시그니처 */
typedef int (*PcreCompareFunc)(const char *k1, uint16_t l1, const char *k2, uint16_t l2);


/** 메모리 해제 함수 시그니처 */
typedef void (*PcreFreeFunc)(void *data);


/**
 * @brief PCRE 캐시 엔트리 구조체
 * @note 이 구조체는 PCRE 정규식 캐시 테이블의 각 항목을 나타냄
 */
typedef struct PcreCacheEntry {
    char *rule_id;                  /** 룰 ID (체인의 경우 베이스 ID) */
    pcre2_code *re;                 /** PCRE 컴파일 결과 */
    int is_negated;                 /** 부정 조건 여부 */
    struct PcreCacheEntry *next;    /** 다음 체인 단계 (체인일 경우) */
} PcreCacheEntry;


/**
 * @brief 해시 테이블의 각 버킷을 나타내는 구조체
 * @note 이 구조체는 해시 테이블에서 키-값 쌍을 저장하는 데 사용
 */
typedef struct Bucket_ {
    char *key;              /** 해시 키 */
    uint16_t key_len;       /** 해시 키 길이 */
    void *data;             /** 해시 값 (PCRE 캐시 엔트리) */
    struct Bucket_ *next;   /** 다음 버킷 (체인 해시) */
} Bucket;


/**
 * @brief PCRE 캐시 테이블 구조체
 * @note 이 구조체는 해시 테이블을 사용하여 PCRE 정규식을 캐시하는 데 사용
 *       각 버킷은 해시 키와 값을 저장하며, 체인 해시를 사용하여 충돌을 처리
 */
typedef struct PcreCacheTable_ {
    Bucket **buckets;           /** 해시 테이블의 버킷 배열 */
    uint32_t size;              /** 해시 테이블의 크기 */
    PcreHashFunc hash_func;     /** 해시 함수 */
    PcreCompareFunc cmp_func;   /** 문자열 비교 함수 */
    PcreFreeFunc free_func;     /** 메모리 해제 함수 */
} PcreCacheTable;


/** HS-only 캐시 테이블 반환 함수 */
PcreCacheTable *HsCacheTableGetGlobal(void);


/** PCRE-only 캐시 테이블 반환 함수 */
PcreCacheTable *PcreOnlyCacheTableGetGlobal(void);


/** 체인 캐시 테이블 반환 함수 */
PcreCacheTable *ChainCacheTableGetGlobal(void);


/** 캐시 테이블 생성 함수 */
PcreCacheTable *CreatePcreCacheTable(uint32_t size,
                                     PcreHashFunc hash,
                                     PcreCompareFunc cmp,
                                     PcreFreeFunc free_func);

/** 캐시 테이블 초기화 함수 */
int PcreCacheTableInit(void);


/** 캐시 테이블 해제 함수 */
void DestroyPcreCacheTable(PcreCacheTable *table);


/** HS-only 캐시 테이블 항목 추가 함수 */
int PcreCacheTableAddToHsCache(const char *rule_id, pcre2_code *re, int is_negated);


/** PCRE-only 캐시 테이블 항목 추가 함수 */
int PcreCacheTableAddToPcreCache(const char *rule_id, pcre2_code *re, int is_negated);


/** 체인 캐시 테이블 항목 추가 함수 */
int PcreCacheTableAddChain(const char *rule_id, unsigned long step, pcre2_code *re, int is_negated);


/** 캐시 테이블 항목 추가 함수 */
int PcreCacheTableInsert(PcreCacheTable *t, const char *key, uint16_t len, void *data);


/** 캐시 테이블 항목 조회 함수 */
void *PcreCacheTableLookup(PcreCacheTable *table, const char *key, uint16_t len);


/** 캐시 테이블 해제 함수 */
void PcreCacheTableFree(void);


/** 캐시 테이블 덤프 함수 */
void PcreCacheTableDump(PcreCacheTable *table);


/** PCRE 캐시 엔트리 메모리 해제 함수 */
void FreePcreEntry(void *data);


/** 체인 캐시 엔트리 메모리 해제 함수 */
void FreePcreChainEntry(void *data);


/** PCRE-only 룰 ID가 부정 조건인지 확인하는 함수 */
int PcreCacheTableIsNegated(const char *rule_id);

#endif /* SWAF_PCRE_CACHE_TABLE_H */
