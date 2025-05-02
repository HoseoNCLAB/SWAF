#include <iostream>
#include <memory>

#include "no_match.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // NoMatch 오퍼레이터 객체 생성
    modsecurity::operators::NoMatch noMatchOp;

    // 테스트할 입력값
    std::string inputValue = "ANYTHING";

    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    bool result = noMatchOp.evaluate(&transaction, &rule, inputValue, ruleMessage);

    if (result) {
        std::cout << "Unexpected: Matched!" << std::endl;
    } else {
        std::cout << "Correct: No match." << std::endl;
    }

    return 0;
}
