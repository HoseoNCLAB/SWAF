#ifndef SRC_OPERATORS_WITHIN_H_
#define SRC_OPERATORS_WITHIN_H_

#include <string>
#include <memory>
#include <utility>

#include "operator.h"             // 종속성 제거된 연산자 기반 클래스
#include "transaction.h"          // Transaction 구조 (더미 포함)
#include "rule_with_actions.h"    // RuleWithActions
#include "rule_message.h"         // RuleMessage 및 logOffset 지원

namespace modsecurity {
namespace operators {

class Within : public Operator {
 public:
    explicit Within(std::unique_ptr<RunTimeString> param)
        : Operator("Within", std::move(param)) {
        m_couldContainsMacro = true;
    }

    // 실제 룰 기반 evaluate (within.cc에서 구현됨)
    bool evaluate(Transaction *transaction, RuleWithActions *rule,
                  const std::string &str, RuleMessage &ruleMessage) override;

    // 기본 evaluate (추상 클래스 해소용)
    bool evaluate(Transaction *transaction, const std::string &str) override {
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *transaction);
        return evaluate(transaction, &dummyRule, str, dummyMsg);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_WITHIN_H_
