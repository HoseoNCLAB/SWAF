# mpm_hs_src

### -- SCHStest_hs.c compile code --

#### g++ -DUNITTESTS -DBUILD_HYPERSCAN -DPCRE2_CODE_UNIT_WIDTH=8 -std=c++11   -o SCHStest_hs   SCHStest_hs.c swaf_hs_engine.c swaf_hs_loader.c swaf_match_executor.c   swaf_pcre_capture_eval.c swaf_json_loader.c   mpm.c   mpm_hs.c mpm_hs_core.c mpm_hs_cache.c prefilter.c hash_table.c   hyperscan.c path.c hash_lookup3.c unittest.c   -I. -I/usr/local/include/hs -lhs -ljansson -lpcre2-8


### -- swaf_hs_compile_match_test.c compile code --

#### g++ -std=c++11 -DPCRE2_CODE_UNIT_WIDTH=8 -DUNITTESTS -DBUILD_HYPERSCAN   -o swaf_hs_compile_match_test swaf_hs_compile_match_test.c swaf_hs_loader.c swaf_hs_matcher.c   mpm.c mpm_hs.c mpm_hs_core.c mpm_hs_cache.c   prefilter.c hash_table.c hash_lookup3.c path.c  unittest.c   -I. -I/usr/local/include/hs -lhs -ljansson -lpcre2-8


### -- swaf_pcre_compile_match_test.c compile code --

#### g++ -o swaf_pcre_compile_match_test swaf_pcre_compile_match_test.c swaf_pcre_loader.c swaf_pcre_cache_table.c swaf_pcre_matcher.c swaf_pcre_capture.c -ljansson -lpcre2-8