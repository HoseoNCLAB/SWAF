#include <iostream>
#include <string>
#include <vector>

#include "detect_sqli.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    modsecurity::operators::DetectSQLi op;

    modsecurity::Transaction trans;
    modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
    modsecurity::RuleMessage msg(rule, trans);

    std::vector<std::string> testInputs = {
        "1' OR '1'='1",             // ✅ SQLi
        "SELECT * FROM users",      // ✅ SQLi
        "hello world",              // ❌ 정상
        "admin'--",                 // ✅ SQLi
        "abc=123",                  // ❌ 정상
        "1 OR 1=1",                 // ✅ SQLi
        "'; DROP TABLE users;--",   // ✅ SQLi
        "just a regular input"      // ❌ 정상
    };

    for (const auto& input : testInputs) {
        bool result = op.evaluate(&trans, &rule, input, msg);

        std::cout << "Input: \"" << input << "\" --> "
                  << (result ? "[FAIL] SQLi Detected" : "[PASS] Clean")
                  << std::endl;
    }

    return 0;
}
