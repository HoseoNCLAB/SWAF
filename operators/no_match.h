#ifndef SRC_OPERATORS_NO_MATCH_H_
#define SRC_OPERATORS_NO_MATCH_H_

#include <string>

#include "transaction.h"
#include "operator.h"

namespace modsecurity {
namespace operators {

class NoMatch : public Operator {
 public:
    NoMatch()
        : Operator("NoMatch") { }

    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &str,
                  RuleMessage &ruleMessage) override {
        return evaluate(transaction, str);
    }

    bool evaluate(Transaction *transaction, const std::string &str);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_NO_MATCH_H_
