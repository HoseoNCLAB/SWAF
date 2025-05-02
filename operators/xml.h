#ifndef SRC_REQUEST_BODY_PROCESSOR_XML_H_
#define SRC_REQUEST_BODY_PROCESSOR_XML_H_

#include <libxml/parser.h>
#include <libxml/tree.h>

namespace modsecurity {
namespace RequestBodyProcessor {

// validate_dtd 오퍼레이터에서 사용하는 필드만 남김
struct xml_data {
    xmlDocPtr doc = nullptr;
    unsigned int well_formed = 0;
};

class XML {
 public:
    xml_data m_data;
};

}  // namespace RequestBodyProcessor
}  // namespace modsecurity

#endif  // SRC_REQUEST_BODY_PROCESSOR_XML_H_
