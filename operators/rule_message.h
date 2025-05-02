#ifndef HEADERS_MODSECURITY_RULE_MESSAGE_H_
#define HEADERS_MODSECURITY_RULE_MESSAGE_H_

#include <string>
#include <list>
#include "rule_with_actions.h"
#include "transaction.h"

namespace modsecurity {

class RuleMessage {
 public:
    RuleMessage(RuleWithActions& rule, Transaction& trans)
        : m_rule(rule), m_transaction(trans) {}

    modsecurity::RuleWithActions& m_rule;
    modsecurity::Transaction& m_transaction;
    std::string m_reference;
};

}  // namespace modsecurity

#endif  // HEADERS_MODSECURITY_RULE_MESSAGE_H_
