#ifndef SRC_OPERATORS_DETECT_XSS_H_
#define SRC_OPERATORS_DETECT_XSS_H_

#include <string>
#include <memory>

#include "operator.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

class DetectXSS : public Operator {
 public:
    DetectXSS()
        : Operator("DetectXSS") {
        // 주의: m_match_message는 종속성 제거 버전 operator.h에 따라 제거 가능
        // m_match_message.assign("detected XSS using libinjection.");
    }

    bool evaluate(Transaction *t, RuleWithActions *rule,
        const std::string& input,
        RuleMessage &ruleMessage) override;

    // 추상 클래스 해소용 기본 evaluate 구현
    bool evaluate(Transaction *t, const std::string& input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *t);
        return evaluate(t, &dummyRule, input, dummyMsg);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_DETECT_XSS_H_
