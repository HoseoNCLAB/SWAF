#ifndef MODSECURITY_OPERATOR_H
#define MODSECURITY_OPERATOR_H

#include <string>
#include <memory>

#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

class Operator {
 public:
    explicit Operator(const std::string &opName)
        : m_op(opName),
          m_negation(false),
          m_param(""),
          m_couldContainsMacro(false) {
        if (!m_couldContainsMacro && m_string) {
            m_param = m_string->evaluate(nullptr);
        }
    }

    Operator(const std::string &opName,
             std::unique_ptr<RunTimeString> param)
        : m_op(opName),
          m_string(std::move(param)),
          m_negation(false),
          m_param(""),
          m_couldContainsMacro(false) {
        if (!m_couldContainsMacro && m_string) {
            m_param = m_string->evaluate(nullptr);
        }
    }

    virtual ~Operator() {}

    virtual bool evaluate(Transaction *transaction, const std::string &str) = 0;

    virtual bool evaluate(Transaction *transaction,
                          RuleWithActions *rule,
                          const std::string &str) {
        return evaluate(transaction, str);
    }

    virtual bool evaluate(Transaction *transaction,
                          RuleWithActions *rule,
                          const std::string &str,
                          RuleMessage &ruleMessage) {
        return evaluate(transaction, str);
    }

    virtual bool init(const std::string &arg, std::string *error) {
        return true;
    }

    static void logOffset(RuleMessage &ruleMessage, int offset, int len) {
        ruleMessage.m_reference.append("o"
            + std::to_string(offset) + "," + std::to_string(len));
    }

 protected:
    std::string m_op;
    std::string m_param;
    bool m_negation;
    std::unique_ptr<RunTimeString> m_string;
    bool m_couldContainsMacro;
};

}  // namespace operators
}  // namespace modsecurity

// ✅ 전역 호출을 위한 inline wrapper 함수
inline void logOffset(modsecurity::RuleMessage &rm, int offset, int len) {
    modsecurity::operators::Operator::logOffset(rm, offset, len);
}

#endif  // MODSECURITY_OPERATOR_H
