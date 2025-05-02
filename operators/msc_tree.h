#ifndef MSC_TREE_H_
#define MSC_TREE_H_

#include <string>
#include <vector>

namespace modsecurity {
namespace Utils {

template <typename T>
class MSCTree {
 public:
    MSCTree() = default;
    ~MSCTree() = default;

    // IP 저장
    void insert(const T& item) {
        m_items.push_back(item);
    }

    // IP 매칭 검사
    bool contains(const T& item) const {
        for (const auto& stored : m_items) {
            if (stored == item) {
                return true;
            }
        }
        return false;
    }

 private:
    std::vector<T> m_items;
};

}  // namespace Utils
}  // namespace modsecurity

#endif  // MSC_TREE_H_
