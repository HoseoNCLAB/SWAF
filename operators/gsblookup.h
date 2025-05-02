#ifndef GSBLOOKUP_H_
#define GSBLOOKUP_H_

#include <string>
#include <memory>
#include <utility>

#include "operator.h"

namespace modsecurity {
namespace operators {

class GsbLookup : public Operator {
 public:
    explicit GsbLookup(std::unique_ptr<RunTimeString> param)
        : Operator("GsbLookup", std::move(param)) { }

    bool evaluate(Transaction *transaction, const std::string &str) override;  // ✅ 2개 인자 버전으로 수정
};

}  // namespace operators
}  // namespace modsecurity

#endif  // GSBLOOKUP_H_
