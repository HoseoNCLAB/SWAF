#ifndef IP_MATCH_H_
#define IP_MATCH_H_

#include <string>
#include <memory>

#include "operator.h"
#include "ip_tree.h"

namespace modsecurity {
namespace operators {

class IpMatch : public Operator {
 public:
    explicit IpMatch(std::unique_ptr<RunTimeString> param)
        : Operator("IpMatch", std::move(param)) {}

    // 🔥 4개 인자 레퍼런스(&) 버전 정확히 맞추기
    bool evaluate(Transaction *transaction,
                  RuleWithActions *rule,
                  const std::string &input,
                  RuleMessage &ruleMessage) override {
        return evaluate(transaction, input);
    }

    bool evaluate(Transaction *transaction, const std::string &input);

    bool init(const std::string& arg, std::string* err);

protected:
    Utils::IpTree m_tree;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // IP_MATCH_H_
