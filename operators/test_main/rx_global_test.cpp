#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include "rx_global.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

// logOffset 더미 정의
namespace modsecurity {
namespace operators {
    void logOffset(modsecurity::RuleMessage &ruleMessage, int offset, int len) {
        ruleMessage.m_reference.append("o" + std::to_string(offset) + "," + std::to_string(len));
    }
}  // namespace operators
}  // namespace modsecurity

int main() {
    std::string input = "aaa12bbb412345ccc7891234ddddd4234324";

    auto param = std::make_unique<modsecurity::RunTimeString>("[0-9]+");
    modsecurity::operators::RxGlobal rxg_op(std::move(param));
    std::string error;
    rxg_op.init("[0-9]+", &error);

    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions dummy_rule(nullptr, nullptr, "dummy.conf", 1);
    modsecurity::RuleMessage rule_msg(dummy_rule, transaction);

    bool result = rxg_op.evaluate(&transaction, &dummy_rule, input, rule_msg);

    std::cout << "[INPUT] " << input << "\n";
    std::cout << "→ Matched: " << (result ? "✔ YES" : "✘ NO") << "\n";
    std::cout << "→ Captures:\n";
    for (size_t i = 0; i < transaction.m_matched.size(); ++i) {
        std::cout << "  TX." << i << " = " << transaction.m_matched[i] << "\n";
    }

    return 0;
}
