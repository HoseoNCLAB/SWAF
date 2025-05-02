#ifndef MODSECURITY_CONTAINS_WORD_H
#define MODSECURITY_CONTAINS_WORD_H

#include <string>
#include <memory>
#include <cctype>
#include "operator.h"

namespace modsecurity {
namespace operators {

class ContainsWord : public Operator {
 public:
    explicit ContainsWord(std::unique_ptr<RunTimeString> param)
        : Operator("ContainsWord", std::move(param)), m_string(std::move(param)) { }

    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage);

 private:
    std::unique_ptr<RunTimeString> m_string;

    static inline bool acceptableChar(char c) {
        return std::isalnum(c) || c == '-' || c == '_';
    }

    // ✅ 선언만 남김! 구현은 cc에 있음
    static bool acceptableChar(const std::string& str, size_t pos);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // MODSECURITY_CONTAINS_WORD_H
