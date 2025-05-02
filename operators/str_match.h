#ifndef SRC_OPERATORS_STR_MATCH_H_
#define SRC_OPERATORS_STR_MATCH_H_

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

class StrMatch : public Operator {
 public:
    explicit StrMatch(std::unique_ptr<RunTimeString> param)
        : Operator("StrMatch", std::move(param)) {
            m_couldContainsMacro = true;
        }

    // 이 시그니처는 .cc에 존재해야 함
    bool evaluate(Transaction* transaction, const std::string& input);

    // Operator 인터페이스용 4인자 오버라이드
    bool evaluate(Transaction* transaction,
                  RuleWithActions*,
                  const std::string& input,
                  RuleMessage&) override {
        return evaluate(transaction, input);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_STR_MATCH_H_
