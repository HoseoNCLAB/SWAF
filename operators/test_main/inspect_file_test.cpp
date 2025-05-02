#include <iostream>
#include <memory>

#include "inspect_file.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    using namespace modsecurity::operators;

    std::unique_ptr<modsecurity::RunTimeString> param(new modsecurity::RunTimeString("example.lua"));
    InspectFile inspect(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    std::string dummyInput = "example.lua";

    bool result = inspect.evaluate(&tx, &rule, dummyInput, ruleMessage);

    if (result) {
        std::cout << "InspectFile success! (Lua script executed successfully)" << std::endl;
    } else {
        std::cout << "InspectFile failed! (Lua script execution failed)" << std::endl;
    }

    return 0;
}
