#ifndef HEADERS_MODSECURITY_RULE_WITH_ACTIONS_H_
#define HEADERS_MODSECURITY_RULE_WITH_ACTIONS_H_

namespace modsecurity {

class RuleWithActions {
 public:
    RuleWithActions(void*, void*, const std::string& f, int l) {}
    bool hasCaptureAction() const { return true; }
};

}  // namespace modsecurity

#endif  // HEADERS_MODSECURITY_RULE_WITH_ACTIONS_H_
