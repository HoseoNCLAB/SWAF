#ifndef SRC_OPERATORS_STR_EQ_H_
#define SRC_OPERATORS_STR_EQ_H_

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

class StrEq : public Operator {
 public:
    explicit StrEq(std::unique_ptr<RunTimeString> param)
        : Operator("StrEq", std::move(param)) { }

    // 2인자 버전 (str_eq.cc에서 구현됨)
    bool evaluate(Transaction* transaction, const std::string& str);

    // 4인자 오버라이드 버전 (여기서 인라인 정의)
    bool evaluate(Transaction* transaction,
                  RuleWithActions* /*rule*/,
                  const std::string& str,
                  RuleMessage& /*ruleMessage*/) override {
        return evaluate(transaction, str);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_STR_EQ_H_
