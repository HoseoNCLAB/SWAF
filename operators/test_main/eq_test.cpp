#include <iostream>
#include "eq.h"
#include "transaction.h"
#include "run_time_string.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    auto param = std::make_unique<modsecurity::RunTimeString>("1234");
    modsecurity::operators::Eq op(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    std::string input = "123";
    bool result = op.evaluate(&tx, &rule, input, msg);

    std::cout << "[RESULT] Eq evaluation: " << (result ? "Matched ✅" : "Not matched ❌") << std::endl;
    return 0;
}
