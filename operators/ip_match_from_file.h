#ifndef IP_MATCH_FROM_FILE_H_
#define IP_MATCH_FROM_FILE_H_

#include <string>
#include <memory>

#include "operator.h"
#include "ip_match.h"

namespace modsecurity {
namespace operators {

class IpMatchFromFile : public IpMatch {
 public:
    explicit IpMatchFromFile(std::unique_ptr<RunTimeString> param)
        : IpMatch(std::move(param)) {}

    bool init(const std::string& filePath, std::string* error);
};

}  // namespace operators
}  // namespace modsecurity

#endif  // IP_MATCH_FROM_FILE_H_
