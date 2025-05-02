#ifndef SRC_OPERATORS_IP_MATCH_F_H_
#define SRC_OPERATORS_IP_MATCH_F_H_

#include <string>
#include <memory>
#include <utility>

#include "ip_match_from_file.h"  // 경로 수정 완료

namespace modsecurity {
namespace operators {

class IpMatchF : public IpMatchFromFile {
 public:
    explicit IpMatchF(std::unique_ptr<RunTimeString> param)
        : IpMatchFromFile(std::move(param)) { }
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_IP_MATCH_F_H_
