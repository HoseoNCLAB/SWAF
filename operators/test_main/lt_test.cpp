#include <iostream>
#include <memory>

#include "lt.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // 비교 기준값을 5로 세팅
    auto runtimeString = std::make_unique<modsecurity::RunTimeString>("5");

    // Lt 오퍼레이터 객체 생성
    modsecurity::operators::Lt ltOp(std::move(runtimeString));

    // 테스트할 입력값 (예: 3)
    std::string inputValue = "3";

    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    bool result = ltOp.evaluate(&transaction, &rule, inputValue, ruleMessage);

    if (result) {
        std::cout << "Input " << inputValue << " is less than 5" << std::endl;
    } else {
        std::cout << "Input " << inputValue << " is NOT less than 5" << std::endl;
    }

    return 0;
}
