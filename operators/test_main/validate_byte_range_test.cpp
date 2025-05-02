#ifndef SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_
#define SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_

#include <string>
#include <vector>
#include <cstring>
#include <memory>

#include "operator.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "run_time_string.h"

namespace modsecurity {
namespace operators {

class ValidateByteRange : public Operator {
 public:
    explicit ValidateByteRange(std::unique_ptr<RunTimeString> param)
        : Operator("ValidateByteRange", std::move(param)) {
        std::memset(table, '\0', sizeof(char) * 32);
    }

    ~ValidateByteRange() override {}

    // ✅ 추가: 2인자 버전 오버라이드 (필수!)
    bool evaluate(Transaction *transaction,
                  const std::string &input) override {
        // 실제로는 4인자 버전만 구현되어 있으므로 이건 그냥 위임해도 됨
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *transaction);
        return evaluate(transaction, &dummyRule, input, dummyMsg);
    }

    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage) override;

    bool getRange(const std::string &rangeRepresentation, std::string *error);

    bool init(const std::string &arg, std::string *error) override;

 private:
    std::vector<std::string> ranges;
    char table[32];
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VALIDATE_BYTE_RANGE_H_
