#ifndef SRC_OPERATORS_VALIDATE_DTD_H_
#define SRC_OPERATORS_VALIDATE_DTD_H_

// ✅ 테스트를 위해 LIBXML2 사용 강제 지정
#define WITH_LIBXML2

#include <string>
#include <memory>

#ifdef WITH_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xmlschemas.h>

// ✅ xmlSchemaValidityErrorFunc 직접 정의 (링크 오류 방지)
typedef void (*xmlSchemaValidityErrorFunc)(void *, const char *, ...);
#endif

#include "operator.h"
#include "transaction.h"
#include "run_time_string.h"
#include "rule_with_actions.h"
#include "rule_message.h"

namespace modsecurity {
namespace operators {

#ifdef WITH_LIBXML2
class XmlDtdPtrManager {
 public:
    explicit XmlDtdPtrManager(xmlDtdPtr dtd)
        : m_dtd(dtd) { }

    ~XmlDtdPtrManager() {
        if (m_dtd != NULL) {
            xmlFreeDtd(m_dtd);
            m_dtd = NULL;
        }
    }

    xmlDtdPtr get() const { return m_dtd; }

 private:
    xmlDtdPtr m_dtd;
};
#endif  // WITH_LIBXML2

class ValidateDTD : public Operator {
 public:
    explicit ValidateDTD(std::unique_ptr<RunTimeString> param)
        : Operator("ValidateDTD", std::move(param)) { }

#ifdef WITH_LIBXML2
    bool evaluate(Transaction *transaction, const std::string &str) override;
    bool init(const std::string &file, std::string *error) override;

    static void error_runtime(void *ctx, const char *msg, ...) {
        va_list args;
        va_start(args, msg);
        vfprintf(stderr, msg, args);
        fprintf(stderr, "\n");
        va_end(args);
    }

    static void warn_runtime(void *ctx, const char *msg, ...) {
        va_list args;
        va_start(args, msg);
        vfprintf(stderr, msg, args);
        fprintf(stderr, "\n");
        va_end(args);
    }

    static void null_error(void *, const char *, ...) {
        // no-op for testing
    }

 private:
    std::string m_resource;
#endif  // WITH_LIBXML2
};

}  // namespace operators
}  // namespace modsecurity

#endif  // SRC_OPERATORS_VALIDATE_DTD_H_
