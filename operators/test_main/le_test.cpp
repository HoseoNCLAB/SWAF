#include <iostream>
#include <memory>

#include "le.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // 테스트용 비교값 세팅 (5보다 작거나 같은 값이면 통과)
    auto runtimeString = std::make_unique<modsecurity::RunTimeString>("5");

    // Le 오퍼레이터 객체 생성
    modsecurity::operators::Le leOp(std::move(runtimeString));

    // 테스트용 입력값 (여기서는 3을 입력해본다)
    std::string inputValue = "3";

    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    bool result = leOp.evaluate(&transaction, &rule, inputValue, ruleMessage);

    if (result) {
        std::cout << "Input " << inputValue << " is less than or equal to 5" << std::endl;
    } else {
        std::cout << "Input " << inputValue << " is greater than 5" << std::endl;
    }

    return 0;
}
