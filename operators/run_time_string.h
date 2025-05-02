#ifndef SRC_RUN_TIME_STRING_H_
#define SRC_RUN_TIME_STRING_H_

#include <string>

namespace modsecurity {

class RunTimeString {
 public:
    RunTimeString() = default;
    RunTimeString(const std::string& v) : value(v) {}

    std::string evaluate(void* /*transaction*/) const {
        return value;
    }

    bool m_containsMacro = false;

 private:
    std::string value;
};

}  // namespace modsecurity

#endif  // SRC_RUN_TIME_STRING_H_
