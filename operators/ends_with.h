#ifndef SRC_OPERATORS_ENDS_WITH_H_
#define SRC_OPERATORS_ENDS_WITH_H_

#include <string>
#include <memory>
#include "operator.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

class EndsWith : public Operator {
 public:
    explicit EndsWith(std::unique_ptr<RunTimeString> param)
        : Operator("EndsWith", std::move(param)) {
            m_couldContainsMacro = true;
        }

    bool evaluate(Transaction *transaction, RuleWithActions *rule,
                  const std::string &str,
                  RuleMessage &ruleMessage) override;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_ENDS_WITH_H_
