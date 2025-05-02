#ifndef SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_
#define SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_

#include <string>
#include <memory>

#include "operator.h"             // 종속성 제거된 공통 연산자 클래스
#include "transaction.h"          // Transaction 구조
#include "rule_with_actions.h"    // RuleWithActions
#include "rule_message.h"         // RuleMessage (logOffset, capture 등)
#include "debug_log.h"         // ms_dbg_a (디버그 메시지 출력)

namespace modsecurity {
namespace operators {

class ValidateUtf8Encoding : public Operator {
 public:
    ValidateUtf8Encoding()
        : Operator("ValidateUtf8Encoding") { }

    // ✅ Operator 인터페이스 충족을 위한 필수 구현 (추상 클래스 해결용)
    bool evaluate(Transaction *transaction, const std::string &str) override {
        RuleWithActions dummyRule(nullptr, nullptr, "dummy.cpp", 1);
        RuleMessage dummyMsg(dummyRule, *transaction);
        return evaluate(transaction, &dummyRule, str, dummyMsg);
    }

    // ✅ 실제 호출되는 ModSecurity용 evaluate 함수
    bool evaluate(Transaction *transaction, RuleWithActions *rule,
                  const std::string &str,
                  RuleMessage &ruleMessage) override;

    // UTF-8 문자 1개 단위 추출 (내부용)
    static int detect_utf8_character(const unsigned char *p_read,
                                     unsigned int length);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VALIDATE_UTF8_ENCODING_H_
