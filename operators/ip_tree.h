#ifndef IP_TREE_H_
#define IP_TREE_H_

#include <string>
#include <memory>
#include <fstream>  // 파일 읽기용 추가
#include <sstream>
#include "msc_tree.h"

namespace modsecurity {
namespace Utils {

class IpTree {
 public:
    IpTree() = default;
    ~IpTree() = default;

    bool addFromBuffer(const std::string& buffer, std::string* /*error*/) {
        m_tree->insert(buffer);
        return true;
    }

    bool addFromFile(const std::string& filePath, std::string* err) {
        std::ifstream infile(filePath);
        if (!infile.is_open()) {
            if (err) {
                *err = "Failed to open file: " + filePath;
            }
            return false;
        }

        std::string line;
        while (std::getline(infile, line)) {
            // 빈 줄 무시
            if (line.empty()) {
                continue;
            }
            // 공백 제거
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (!line.empty()) {
                m_tree->insert(line);
            }
        }

        infile.close();
        return true;
    }

    bool addFromUrl(const std::string& url, std::string* /*error*/) {
        // URL 로딩은 아직 더미
        m_tree->insert(url);
        return true;
    }

    bool contains(const std::string& ip) const {
        return m_tree->contains(ip);
    }

 private:
    std::unique_ptr<MSCTree<std::string>> m_tree = std::make_unique<MSCTree<std::string>>();
};

}  // namespace Utils
}  // namespace modsecurity

#endif  // IP_TREE_H_
