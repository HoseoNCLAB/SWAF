#include <iostream>
#include <memory>
#include <string>

#include "validate_schema.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

int main() {
    // 1. 사용할 XML 스키마(XSD) 파일명 설정
    std::unique_ptr<modsecurity::RunTimeString> param(
        new modsecurity::RunTimeString("example.xsd")
    );

    modsecurity::operators::ValidateSchema op(std::move(param));

    // 2. 오퍼레이터 초기화
    std::string initError;
    if (!op.init(".", &initError)) {
        std::cerr << "Init failed: " << initError << std::endl;
        return 1;
    }

    // 3. XML 문서 생성
    modsecurity::Transaction trans;

    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    xmlNodePtr child = xmlNewChild(root, NULL, BAD_CAST "name", BAD_CAST "혜진");

    xmlDocSetRootElement(doc, root);

    trans.m_xml->m_data.doc = doc;
    trans.m_xml->m_data.well_formed = 1;

    // 4. 룰 및 메시지 생성
    modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
    modsecurity::RuleMessage msg(rule, trans);

    std::string dummyInput = "";  // 실제 사용되지 않음
    bool result = op.evaluate(&trans, dummyInput);

    std::cout << (result ? "[FAIL] Invalid XML" : "[PASS] Valid XML") << std::endl;

    xmlFreeDoc(doc);
    return 0;
}
