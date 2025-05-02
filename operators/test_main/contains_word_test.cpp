#include <iostream>
#include "contains_word.h"
#include "rule_with_actions.h"
#include "transaction.h"
#include "rule_message.h"
#include "run_time_string.h"

int main() {
    auto param = std::make_unique<modsecurity::RunTimeString>();
    modsecurity::operators::ContainsWord op(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    std::string input = "my-password_is-secure";
    bool result = op.evaluate(&tx, &rule, input, msg);

    std::cout << "Result: " << (result ? "Matched ✅" : "Not matched ❌") << std::endl;
    return 0;
}
