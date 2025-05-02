#ifndef SRC_OPERATORS_VALIDATE_URL_ENCODING_H_
#define SRC_OPERATORS_VALIDATE_URL_ENCODING_H_

#include <string>
#include <memory>

#include "operator.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

namespace modsecurity {
namespace operators {

class ValidateUrlEncoding : public Operator {
 public:
    ValidateUrlEncoding()
        : Operator("ValidateUrlEncoding") { }

    // ✅ Operator의 순수 가상 함수 구현 (.cc 수정 없이 .h에서 정의)
    bool evaluate(Transaction *transaction, const std::string &input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *transaction);
        return evaluate(transaction, &dummyRule, input, dummyMsg);
    }

    // ✅ 실제 오버라이드 함수 (.cc에서 이미 구현됨)
    bool evaluate(Transaction *transaction, RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage) override;

    static int validate_url_encoding(const char *input, uint64_t input_length,
                                     size_t *offset);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VALIDATE_URL_ENCODING_H_
