#ifndef MODSECURITY_OPERATORS_GEO_LOOKUP_H_
#define MODSECURITY_OPERATORS_GEO_LOOKUP_H_

#include <memory>
#include <string>

namespace modsecurity {

// ✅ RunTimeString 더미 정의 추가
class RunTimeString {
 public:
    RunTimeString() = default;
    std::string evaluate() const { return ""; }
};

class Transaction;  // Transaction은 여전히 전방 선언 (main.cpp에 더미 정의)

namespace operators {

// ✅ Operator 클래스 (ModSecurity 스타일)
class Operator {
 public:
    Operator(const std::string& opName,
             std::unique_ptr<RunTimeString> param = nullptr)
        : m_name(opName), m_string(std::move(param)), m_couldContainsMacro(false) {}

    virtual ~Operator() = default;

    virtual bool evaluate(Transaction* transaction, const std::string& str) = 0;

 protected:
    std::string m_name;
    std::unique_ptr<RunTimeString> m_string;
    bool m_couldContainsMacro;
};

// ✅ GeoLookup 오퍼레이터
class GeoLookup : public Operator {
 public:
    GeoLookup()
        : Operator("GeoLookup") {}

    bool evaluate(Transaction* transaction, const std::string& str) override;
};

}  // namespace operators
}  // namespace modsecurity

#endif  // MODSECURITY_OPERATORS_GEO_LOOKUP_H_
