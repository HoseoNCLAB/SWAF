#ifndef MODSECURITY_TRANSACTION_H_
#define MODSECURITY_TRANSACTION_H_

#include <string>
#include <vector>
#include <memory>  // for std::unique_ptr

#ifdef WITH_XML_SUPPORT
#include "xml.h"  // XML 파서가 필요한 경우만 포함
#endif

namespace modsecurity {

// 더미 컬렉션 클래스
struct Collection {
    void storeOrUpdateFirst(const std::string &key, const std::string &value) {
        // 테스트용 no-op
    }
};

// 더미 컬렉션 그룹
struct Collections {
    Collection *m_tx_collection = new Collection();
};

// PCRE Match Limit 구조
struct MatchLimit {
    bool m_set = true;
    unsigned long m_value = 1000;
};

// 룰 설정 구조 (rx, rbl 등에서 사용)
struct Rules {
    struct HttpBlKey {
        bool m_set = true;
        std::string m_value = "dummykey";
    } m_httpblKey;

    MatchLimit m_pcreMatchLimit;
};

// 더미 변수 저장 인터페이스
class VariableDummy {
 public:
    void set(const std::string &key, int offset) {}
};

// ✅ 최종 Transaction 클래스
class Transaction {
public:
    Collections m_collections;
    Rules *m_rules = new Rules();
    std::vector<std::string> m_matched;

    int m_variableOffset = 0;
    VariableDummy m_variableMscPcreError;
    VariableDummy m_variableMscPcreLimitsExceeded;

#ifdef WITH_XML_SUPPORT
    std::unique_ptr<RequestBodyProcessor::XML> m_xml;

    Transaction() {
        m_xml = std::unique_ptr<RequestBodyProcessor::XML>(
            new RequestBodyProcessor::XML()
        );
    }
#else
    Transaction() = default;
#endif
};

}  // namespace modsecurity

#endif  // MODSECURITY_TRANSACTION_H_
