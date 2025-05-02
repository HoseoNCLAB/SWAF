#include <iostream>
#include "contains.h"
#include "rule_with_actions.h"  // ✅ 반드시 포함해야 객체 생성 가능

int main() {
    auto param = std::make_unique<modsecurity::RunTimeString>();
    modsecurity::operators::Contains op(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    std::string input = "hello_contains_test";
    bool result = op.evaluate(&tx, &rule, input, msg);

    std::cout << "Result: " << (result ? "Matched ✅" : "Not matched ❌") << std::endl;
    return 0;
}
