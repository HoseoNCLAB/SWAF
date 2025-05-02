#ifndef MODSECURITY_OPERATORS_BEGINS_WITH_H
#define MODSECURITY_OPERATORS_BEGINS_WITH_H

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

using modsecurity::Operator;
using modsecurity::Transaction;
using modsecurity::RuleWithActions;
using modsecurity::RuleMessage;
using modsecurity::RunTimeString;

class BeginsWith : public Operator {
 public:
    explicit BeginsWith(std::unique_ptr<RunTimeString> param)
        : Operator("BeginsWith", std::move(param)),
          m_string(std::move(param)) {}

          bool evaluate(Transaction* transaction,
            RuleWithActions* rule,
            const std::string& str,
            RuleMessage& ruleMessage); 


 private:
    std::unique_ptr<RunTimeString> m_string;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // MODSECURITY_OPERATORS_BEGINS_WITH_H
