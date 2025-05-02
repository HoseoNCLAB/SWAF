#include <iostream>
#include <memory>

#include "gt.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    using namespace modsecurity::operators;

    std::unique_ptr<modsecurity::RunTimeString> param(new modsecurity::RunTimeString("2000"));
    Gt gt(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    std::string inputValue = "100";

    bool result = gt.evaluate(&tx, &rule, inputValue, ruleMessage);

    if (result) {
        std::cout << "Gt success! (input > param)" << std::endl;
    } else {
        std::cout << "Gt failed! (input <= param)" << std::endl;
    }

    return 0;
}
