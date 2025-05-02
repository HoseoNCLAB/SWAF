#include <iostream>
#include "ends_with.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "run_time_string.h"

int main() {
    auto param = std::make_unique<modsecurity::RunTimeString>("world");
    modsecurity::operators::EndsWith op(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    std::string input = "hello world";
    bool result = op.evaluate(&tx, &rule, input, msg);

    std::cout << "[RESULT] EndsWith evaluation: " << (result ? "Matched ✅" : "Not matched ❌") << std::endl;
    return 0;
}
