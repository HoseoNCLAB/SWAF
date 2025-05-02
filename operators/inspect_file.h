#ifndef INSPECT_FILE_H_
#define INSPECT_FILE_H_

#include <string>
#include <memory>
#include <utility>
#include <fstream>   // 🔥 추가
#include <sstream>   // 🔥 추가

#include "operator.h"
#include "system.h"
#include "lua.h"

namespace modsecurity {
namespace operators {

class InspectFile : public Operator {
 public:
    explicit InspectFile(std::unique_ptr<RunTimeString> param)
        : Operator("InspectFile", std::move(param)),
          m_isScript(true) { }

    bool evaluate(Transaction *transaction, const std::string &input);

    bool evaluate(Transaction *transaction,
                  RuleWithActions * /*rule*/,
                  const std::string &input,
                  RuleMessage & /*ruleMessage*/) override {
        return evaluate(transaction, input);
    }

    bool init(const std::string& arg, std::string *err);

 private:
    std::string m_file;
    bool m_isScript;
    engine::Lua m_lua;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // INSPECT_FILE_H_
