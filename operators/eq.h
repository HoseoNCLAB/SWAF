#ifndef SRC_OPERATORS_EQ_H_
#define SRC_OPERATORS_EQ_H_

#include <string>
#include <memory>
#include "operator.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

class Eq : public Operator {
 public:
    explicit Eq(std::unique_ptr<RunTimeString> param)
        : Operator("Eq", std::move(param)) { }

    // ✅ 기존 eq.cc에 있는 함수와 시그니처 일치 (직접 호출될 것)
    bool evaluate(Transaction *transaction, const std::string &input);

    // ✅ ModSecurity 인터페이스용 오버로드 → 내부에서 위 함수 호출
    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage) override {
        return evaluate(transaction, input);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_EQ_H_
