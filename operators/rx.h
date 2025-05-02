#ifndef SRC_OPERATORS_RX_H_
#define SRC_OPERATORS_RX_H_

#include <string>
#include <memory>
#include <vector>

#include "operator.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "regex.h"
using modsecurity::Utils::Regex;

namespace modsecurity {
namespace operators {
void logOffset(RuleMessage &ruleMessage, int offset, int len);
class Rx : public Operator {
 public:
    explicit Rx(std::unique_ptr<RunTimeString> param)
        : m_re(nullptr),
        Operator("Rx", std::move(param)) {
            m_couldContainsMacro = true;
        }

    ~Rx() override {
        if (m_string && m_string->m_containsMacro == false && m_re != nullptr) {
            delete m_re;
            m_re = nullptr;
        }
    }

    bool evaluate(Transaction *transaction, RuleWithActions *rule,
        const std::string& input, RuleMessage &ruleMessage) override;

    bool init(const std::string &arg, std::string *error) override;

 private:
    Utils::Regex *m_re;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_RX_H_
