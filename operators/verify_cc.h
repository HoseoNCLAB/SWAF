#ifndef SRC_OPERATORS_VERIFY_CC_H_
#define SRC_OPERATORS_VERIFY_CC_H_

#ifndef WITH_PCRE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

#include <string>
#include <memory>
#include <utility>
#include <cstring>

#include "operator.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

namespace modsecurity {
namespace operators {

class VerifyCC : public Operator {
 public:
    explicit VerifyCC(std::unique_ptr<RunTimeString> param)
        : Operator("VerifyCC", std::move(param)),
#ifndef WITH_PCRE
          m_pc(nullptr),
          m_pcje(PCRE2_ERROR_JIT_BADOPTION) { }
#else
          m_pc(nullptr),
          m_pce(nullptr) { }
#endif

    ~VerifyCC() override;

    // CRS에서 사용하는 기본 evaluate()
    bool evaluate(Transaction *t, const std::string &input) override {
        RuleWithActions dummyRule(nullptr, nullptr, "", 0);
        RuleMessage dummyMsg(dummyRule, *t);
        return evaluate(t, &dummyRule, input, dummyMsg);
    }

    // 실제 규칙 적용용 evaluate()
    bool evaluate(Transaction *t, RuleWithActions *rule,
                  const std::string& input,
                  RuleMessage &ruleMessage) override;

    bool init(const std::string &param, std::string *error) override;

 private:
#ifndef WITH_PCRE
    pcre2_code *m_pc;
    int m_pcje;
#else
    pcre *m_pc;
    pcre_extra *m_pce;
#endif

    static int luhnVerify(const char *ccnumber, int len);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VERIFY_CC_H_
