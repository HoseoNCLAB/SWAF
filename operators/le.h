#ifndef SRC_OPERATORS_LE_H_
#define SRC_OPERATORS_LE_H_

#include <string>
#include <memory>
#include <utility>

#include "operator.h"

namespace modsecurity {
namespace operators {

class Le : public Operator {
 public:
    explicit Le(std::unique_ptr<RunTimeString> param)
        : Operator("Le", std::move(param)) {
            m_couldContainsMacro = true;
        }

    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage) override {
        return evaluate(transaction, input);
    }

    bool evaluate(Transaction *transaction, const std::string &input);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_LE_H_
