#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "validate_utf8_encoding.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    modsecurity::operators::ValidateUtf8Encoding op;

    modsecurity::Transaction trans;
    modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
    modsecurity::RuleMessage msg(rule, trans);

    std::vector<std::string> testInputs = {
        "hello",               // ✅ ASCII → Valid
        "안녕하세요",           // ✅ UTF-8 → Valid
        "😊",                  // ✅ 이모지 (UTF-8) → Valid
        "\xC3\x28",            // ❌ 잘못된 UTF-8 시퀀스 → Invalid
        "\xE2\x82",            // ❌ 불완전한 UTF-8 시퀀스 → Invalid
        "\xF0\x9F\x92\xA9",    // ✅ U+1F4A9 (💩) → Valid
        "\xFF\xFE\xFD",        // ❌ Invalid bytes → Invalid
        "abc\xF0\x28\x8C\x28"  // ❌ 잘못된 시퀀스 포함 → Invalid
    };

    for (const auto& input : testInputs) {
        bool result = op.evaluate(&trans, &rule, input, msg);

        std::cout << "Input: ";
        for (unsigned char ch : input) {
            if (std::isprint(ch))
                std::cout << ch;
            else
                std::cout << "\\x" << std::hex << (int)ch;
        }

        std::cout << " --> "
                  << (result ? "[FAIL] Invalid UTF-8" : "[PASS] Valid UTF-8")
                  << std::endl;
    }

    return 0;
}
