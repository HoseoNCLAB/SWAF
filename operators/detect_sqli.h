#ifndef SRC_OPERATORS_DETECT_SQLI_H_
#define SRC_OPERATORS_DETECT_SQLI_H_

#include <string>
#include <memory>

#include "operator.h"             // 오퍼레이터 기반 클래스
#include "transaction.h"          // Transaction (더미 포함)
#include "rule_with_actions.h"    // RuleWithActions
#include "rule_message.h"         // RuleMessage 및 로그 메시지
#include "debug_log.h"          // 디버그 로그 지원

namespace modsecurity {
namespace operators {

class DetectSQLi : public Operator {
 public:
    DetectSQLi()
        : Operator("DetectSQLi") {
        m_match_message.assign("detected SQLi using libinjection.");
    }

    // 실제 구현 (.cc에 존재)
    bool evaluate(Transaction *t, RuleWithActions *rule,
                  const std::string& input,
                  RuleMessage &ruleMessage) override;

    // 기본 오버라이드 (.cc에 없음 → .h에서 정의)
    bool evaluate(Transaction *t, const std::string& input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *t);
        return evaluate(t, &dummyRule, input, dummyMsg);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_DETECT_SQLI_H_
