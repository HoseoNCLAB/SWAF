#include <iostream>
#include <string>
#include <vector>

#include "detect_xss.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

// libinjection_xss 함수는 C 함수이므로 extern "C" 필요
extern "C" {
    #include "libinjection_xss.h"
}

int main() {
    modsecurity::operators::DetectXSS op;

    std::vector<std::string> testInputs = {
        "<script>alert(1)</script>",          // ✅ 탐지됨
        "<IMG SRC=javascript:alert('XSS')>",  // ✅ 탐지됨
        "<body onload=alert('xss')>",         // ✅ 탐지됨
        "<a href='http://example.com'>Link</a>", // ❌ 정상
        "Hello, world!",                      // ❌ 정상
        "<svg onload=alert(1)>",              // ✅ 탐지됨
        "<div>test</div>",                    // ❌ 정상
        "<iframe src='javascript:alert(1)'></iframe>" // ✅ 탐지됨
    };

    for (const auto& input : testInputs) {
        modsecurity::Transaction trans;
        modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
        modsecurity::RuleMessage msg(rule, trans);

        bool result = op.evaluate(&trans, &rule, input, msg);

        std::cout << "Input: \"" << input << "\" --> "
                  << (result ? "[FAIL] XSS Detected" : "[PASS] Clean")
                  << std::endl;
    }

    return 0;
}
