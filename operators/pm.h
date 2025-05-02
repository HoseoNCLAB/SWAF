#ifndef SRC_OPERATORS_PM_H_
#define SRC_OPERATORS_PM_H_

#include <string>
#include <memory>
#include <utility>
#include <mutex>

#include "operator.h"
#include "acmp.h"
#include "string.h"

namespace modsecurity {
namespace operators {

class Pm : public Operator {
 public:
    explicit Pm(std::unique_ptr<RunTimeString> param)
        : Operator("Pm", std::move(param)) {
        m_p = acmp_create(0);
    }
    explicit Pm(const std::string &n, std::unique_ptr<RunTimeString> param)
        : Operator(n, std::move(param)) {
        m_p = acmp_create(0);
    }
    ~Pm() override;

    bool evaluate(Transaction *transaction, RuleWithActions *rule,
        const std::string &str, RuleMessage &ruleMessage) override;

    bool init(const std::string &file, std::string *error); // <-- override 삭제

    void postOrderTraversal(acmp_btree_node_t *node);
    void cleanup(acmp_node_t *n);

 protected:
    ACMP *m_p;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_PM_H_
