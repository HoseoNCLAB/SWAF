#ifndef SWAF_PCRE_CACHE_TABLE_H
#define SWAF_PCRE_CACHE_TABLE_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdint.h>
#include <pcre2.h>

/* PCRE 캐시 테이블 구조체의 전방 선언 */
typedef struct PcreCacheTable_ PcreCacheTable;

/* 해시 함수 시그니처: 문자열 키와 길이를 받아 32비트 해시값 반환 */
typedef uint32_t (*PcreHashFunc)(const char *key, uint16_t len);

/* 비교 함수 시그니처: 두 문자열 키와 길이를 받아 같으면 1, 다르면 0 반환 */
typedef int (*PcreCompareFunc)(const char *k1, uint16_t l1, const char *k2, uint16_t l2);

/* 해제 함수 시그니처: 저장된 데이터 해제를 위한 함수 포인터 */
typedef void (*PcreFreeFunc)(void *data);

/** 
 * 전역 PCRE 캐시 테이블 반환
 * @return 전역 테이블 포인터
 */
PcreCacheTable *PcreCacheTableGetGlobal(void);

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

/* 테이블 메모리 해제 */
void DestroyPcreCacheTable(PcreCacheTable *table);

/**
 * 테이블에 항목 삽입
 * @param table 테이블 포인터
 * @param key 룰 ID 키
 * @param len 키 길이
 * @param data 저장할 데이터 (예: PcreCacheEntry 포인터)
 * @return 성공 시 0, 실패 시 -1
 */
int PcreCacheTableInsert(PcreCacheTable *table, const char *key, uint16_t len, void *data);

/**
 * 테이블에서 키를 기준으로 항목 조회
 * @param table 테이블 포인터
 * @param key 룰 ID 키
 * @param len 키 길이
 * @return 매칭된 데이터 포인터 (없으면 NULL)
 */
void *PcreCacheTableLookup(PcreCacheTable *table, const char *key, uint16_t len);

/* 테이블 내용을 디버그 출력 */
void PcreCacheTableDump(PcreCacheTable *table);

/**
 * 전역 테이블 초기화
 * @return 성공 시 0, 실패 시 -1
 */
int PcreCacheTableInit(void);

/**
 * 전역 테이블에 룰 추가
 * @param rule_id 룰 ID 문자열
 * @param re 컴파일된 PCRE2 정규식 객체
 * @param is_negated 부정 여부 (!@rx일 경우 1)
 * @return 성공 시 0, 실패 시 -1
 */
int PcreCacheTableAdd(const char *rule_id, pcre2_code *re, int is_negated);

/**
 * 룰 ID로 컴파일된 정규식 가져오기
 * @param rule_id 룰 ID 문자열
 * @return pcre2_code 포인터 (없으면 NULL)
 */
pcre2_code *PcreCacheTableGet(const char *rule_id);

/**
 * 해당 룰이 부정 정규식인지 확인
 * @param rule_id 룰 ID 문자열
 * @return 부정 매칭이면 1, 아니면 0
 */
int PcreCacheTableIsNegated(const char *rule_id);

/* 전역 테이블 메모리 해제 */
void PcreCacheTableFree(void);

/* 전역 테이블 항목 디버그 출력 */
void PcreCacheTableDebugDump(void);

#endif
