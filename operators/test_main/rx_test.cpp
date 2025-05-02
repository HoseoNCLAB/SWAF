#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <regex>

#include "rx.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

namespace modsecurity {
namespace operators {
void logOffset(modsecurity::RuleMessage &ruleMessage, int offset, int len) {
    ruleMessage.m_reference.append("o" + std::to_string(offset) + "," + std::to_string(len));
}
}  // namespace operators
}  // namespace modsecurity

int main() {
    // 테스트할 입력값 리스트 (공격/비공격 문자열)
    std::vector<std::string> inputs = {
        "SELECT * FROM users",
        "username=admin'--",
        "<script>alert(1)</script>",
        "DROP TABLE member;",
        "normal string",
        "foo' or 1=1--",
        "abc123"
    };

    // 테스트할 정규표현식 (@rx의 파라미터 부분)
    std::vector<std::string> rx_patterns = {
        "(['\"])",
        "(?i)(select|union|insert|drop|update).*\\b(from|into)\\b",
        "(?i)<script.*?>",
        "(?i)(--|#|\\/\\*)"
    };

    for (const auto& pattern : rx_patterns) {
        std::cout << "=== Testing pattern: @rx " << pattern << " ===\n";

        auto param = std::make_unique<modsecurity::RunTimeString>(pattern);
        modsecurity::operators::Rx rx_op(std::move(param));
        std::string error;
        rx_op.init(pattern, &error);

        for (const auto& input : inputs) {
            modsecurity::Transaction transaction;
            modsecurity::RuleWithActions dummy_rule(nullptr, nullptr, "dummy.conf", 1);
            modsecurity::RuleMessage rule_msg(dummy_rule, transaction);

            bool result = rx_op.evaluate(&transaction, &dummy_rule, input, rule_msg);

            std::cout << "[INPUT] " << input << "\n";
            std::cout << "→ Match: " << (result ? "✔ YES" : "✘ NO") << "\n\n";
        }

        std::cout << "--------------------------------------------\n\n";
    }

    return 0;
}
