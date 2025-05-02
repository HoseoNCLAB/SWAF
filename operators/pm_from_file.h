#ifndef MODSECURITY_OPERATORS_PM_FROM_FILE_H_
#define MODSECURITY_OPERATORS_PM_FROM_FILE_H_

#include <string>
#include <memory>
#include <utility>

#include "pm.h"  // 종속성 제거된 pm.h 사용

namespace modsecurity {
namespace operators {

class PmFromFile : public Pm {
 public:
    explicit PmFromFile(std::unique_ptr<RunTimeString> param)
        : Pm("PmFromFile", std::move(param)) { }

    explicit PmFromFile(const std::string &n, std::unique_ptr<RunTimeString> param)
        : Pm(n, std::move(param)) { }

    bool init(const std::string &file, std::string *error);

 private:
    static bool isComment(const std::string &s);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // MODSECURITY_OPERATORS_PM_FROM_FILE_H_
