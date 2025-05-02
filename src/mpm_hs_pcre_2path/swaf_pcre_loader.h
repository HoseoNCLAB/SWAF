#ifndef __SWAF_PCRE_LOADER_H__
#define __SWAF_PCRE_LOADER_H__

/* PCRE 룰셋 JSON 파일을 로드하고 pcre2_code 객체로 컴파일하여 캐시에 저장 */
int SwafInitPCRE(const char *json_path);

#endif /* __SWAF_PCRE_LOADER_H__ */
