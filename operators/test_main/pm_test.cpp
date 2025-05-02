#include <iostream>
#include <memory>

#include "pm.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // 테스트용 패턴 리스트 (공백 구분: "abc def xyz")
    auto runtimeString = std::make_unique<modsecurity::RunTimeString>("abcd efg xyz");

    // Pm 오퍼레이터 객체 생성
    modsecurity::operators::Pm pmOp(std::move(runtimeString));

    // 초기화 (패턴 등록)
    std::string error;
    pmOp.init("", &error);

    // 테스트할 입력값 (예: "abcdefg")
    std::string inputValue = "abcdefg";

    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage ruleMessage;

    bool result = pmOp.evaluate(&transaction, &rule, inputValue, ruleMessage);

    if (result) {
        std::cout << "Pattern matched!" << std::endl;
    } else {
        std::cout << "No match." << std::endl;
    }

    return 0;
}
