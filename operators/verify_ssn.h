#ifndef SRC_OPERATORS_VERIFY_SSN_H_
#define SRC_OPERATORS_VERIFY_SSN_H_

#include <string>
#include <memory>
#include <utility>
#include <list>
#include <cctype>  // for isdigit

#include "operator.h"
#include "regex.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

namespace modsecurity {
using Utils::SMatch;
using Utils::regex_search;
using Utils::Regex;

namespace operators {

class VerifySSN : public Operator {
 public:
    explicit VerifySSN(std::unique_ptr<RunTimeString> param)
        : Operator("VerifySSN", std::move(param)),
          m_re(std::make_unique<Regex>(m_param)) { }

    bool operator=(const VerifySSN &a) = delete;
    VerifySSN(const VerifySSN &a) = delete;

    // 기본 evaluate() 오버라이딩 추가
    bool evaluate(Transaction *t, const std::string &input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "", 0);
        RuleMessage dummyMsg(dummyRule, *t);
        return evaluate(t, &dummyRule, input, dummyMsg);
    }

    bool evaluate(Transaction *transaction, RuleWithActions *rule,
                  const std::string& input,
                  RuleMessage &ruleMessage) override;

 private:
    static bool verify(const char *ssnumber, int len);
    static int convert_to_int(const char c);

    std::unique_ptr<Regex> m_re;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VERIFY_SSN_H_
