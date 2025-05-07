#ifndef SRC_OPERATORS_VERIFY_CPF_H_
#define SRC_OPERATORS_VERIFY_CPF_H_

#include <string>
#include <memory>
#include <utility>
#include <cstring>
#include <list>

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

class VerifyCPF : public Operator {
 public:
    explicit VerifyCPF(std::unique_ptr<RunTimeString> param)
        : Operator("VerifyCPF", std::move(param)),
          m_re(std::make_unique<Regex>(m_param)) { }

    bool operator=(const VerifyCPF &a) = delete;
    VerifyCPF(const VerifyCPF &a) = delete;

    // 기본 evaluate() 필요 (추상 클래스 해제)
    bool evaluate(Transaction *t, const std::string &input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "", 0);
        RuleMessage dummyMsg(dummyRule, *t);
        return evaluate(t, &dummyRule, input, dummyMsg);
    }

    bool evaluate(Transaction *transaction, RuleWithActions *rule,
        const std::string& input,
        RuleMessage &ruleMessage) override;

    bool verify(const char *ssnumber, int len) const;

 private:
    static int convert_to_int(const char c);
    std::unique_ptr<Regex> m_re;
    const char bad_cpf[12][12] = {
        "00000000000", "01234567890", "11111111111", "22222222222",
        "33333333333", "44444444444", "55555555555", "66666666666",
        "77777777777", "88888888888", "99999999999"
    };
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VERIFY_CPF_H_
