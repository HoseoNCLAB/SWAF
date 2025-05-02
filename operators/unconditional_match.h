#ifndef SRC_OPERATORS_UNCONDITIONAL_MATCH_H_
#define SRC_OPERATORS_UNCONDITIONAL_MATCH_H_

#include <string>
#include "transaction.h"
#include "operator.h"

namespace modsecurity {
namespace operators {

class UnconditionalMatch : public Operator {
 public:
    UnconditionalMatch() : Operator("UnconditionalMatch") { }
    bool evaluate(Transaction *transaction, const std::string &input) override;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_UNCONDITIONAL_MATCH_H_
