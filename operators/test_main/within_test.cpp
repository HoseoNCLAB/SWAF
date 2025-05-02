#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "within.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // "hello world" 안에 입력값이 포함되어야만 true
    std::unique_ptr<modsecurity::RunTimeString> param(
        new modsecurity::RunTimeString("hello world")
    );

    modsecurity::operators::Within op(std::move(param));

    modsecurity::Transaction trans;
    modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
    modsecurity::RuleMessage msg(rule, trans);

    std::vector<std::string> inputs = {
        "hello",        // ✅ 포함 → PASS
        "world",        // ✅ 포함 → PASS
        "lo wo",        // ✅ 포함 → PASS
        "bye",          // ❌ 없음 → FAIL
        "Hello",        // ❌ 대소문자 구분 → FAIL
        "hello world",  // ✅ 전체 포함 → PASS
        "worlds",       // ❌ world는 포함되나 s는 없음 → FAIL
    };

    for (const auto& input : inputs) {
        bool result = op.evaluate(&trans, &rule, input, msg);
        std::cout << "Input: \"" << input << "\" --> "
                  << (result ? "[PASS] Within" : "[FAIL] Not within")
                  << std::endl;
    }

    return 0;
}
