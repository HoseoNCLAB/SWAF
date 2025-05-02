#ifndef SRC_OPERATORS_GE_H_
#define SRC_OPERATORS_GE_H_

#include <string>
#include <memory>
#include <utility>

#include "operator.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

class Ge : public Operator {
 public:
    explicit Ge(std::unique_ptr<RunTimeString> param)
        : Operator("Ge", std::move(param)) {
        m_couldContainsMacro = true;
    }

    // ge.cc에서 정의된 진짜 구현
    bool evaluate(Transaction *transaction, const std::string &input);

    // 여긴 ge.cc에 없음 → 헤더에서 직접 정의
    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &msg) override {
        return evaluate(transaction, input);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_GE_H_
