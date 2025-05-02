#ifndef GSB_GT_H_
#define GSB_GT_H_

#include <string>
#include <memory>
#include <utility>

#include "operator.h"

namespace modsecurity {
namespace operators {

class Gt : public Operator {
 public:
    explicit Gt(std::unique_ptr<RunTimeString> param)
        : Operator("Gt", std::move(param)) { }

    // 2개 인자 evaluate
    bool evaluate(Transaction *transaction, const std::string &input);

    // 4개 인자 evaluate 오버라이드 (inline으로 구현)
    bool evaluate(Transaction *transaction,
                  RuleWithActions * /*rule*/,
                  const std::string &input,
                  RuleMessage & /*ruleMessage*/) override {
        return evaluate(transaction, input);
    }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // GSB_GT_H_
