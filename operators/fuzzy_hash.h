#ifndef SRC_OPERATORS_FUZZY_HASH_H_
#define SRC_OPERATORS_FUZZY_HASH_H_

#include <cstring>   // ✅ strlen, memcpy, strdup 관련
#include <string>
#include <memory>
#include <utility>
#include <fstream>
#include <cstdlib>

#ifdef WITH_SSDEEP
#include <fuzzy.h>
#endif

// strdup 대체 정의 (POSIX 없는 환경 대응)
inline char* safe_strdup(const char* s) noexcept {
    if (!s) return nullptr;
    size_t len = strlen(s) + 1;
    char* p = static_cast<char*>(malloc(len));
    if (p) memcpy(p, s, len);
    return p;
}


#include "operator.h"
#include "transaction.h"
#include "debug_log.h"
#include "system.h"

namespace modsecurity {
namespace operators {

struct fuzzy_hash_chunk {
    std::shared_ptr<char> data;
    std::shared_ptr<fuzzy_hash_chunk> next;
};

class FuzzyHash : public Operator {
 public:
    explicit FuzzyHash(std::unique_ptr<RunTimeString> param)
        : Operator("FuzzyHash", std::move(param)),
          m_threshold(0),
          m_head(nullptr) { }

    ~FuzzyHash() override = default;

    bool evaluate(Transaction *transaction, const std::string &input) override;
    bool init(const std::string &param, std::string *error) override;

 private:
    int m_threshold;
    std::shared_ptr<fuzzy_hash_chunk> m_head;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_FUZZY_HASH_H_
