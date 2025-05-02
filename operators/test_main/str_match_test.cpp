#include <iostream>
#include <memory>
#include <string>

#include "str_match.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    std::string input = "SELECT * FROM users";

    // 비교할 문자열을 RunTimeString으로 설정
    auto param = std::make_unique<modsecurity::RunTimeString>("SELECT");
    modsecurity::operators::StrMatch strmatch_op(std::move(param));

    // 더미 트랜잭션 및 룰 구성
    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions dummy_rule(nullptr, nullptr, "dummy.conf", 1);
    modsecurity::RuleMessage rule_msg(dummy_rule, transaction);

    // 평가 실행
    bool result = strmatch_op.evaluate(&transaction, &dummy_rule, input, rule_msg);

    std::cout << "[INPUT] " << input << std::endl;
    if (result) {
        std::cout << "✔ Matched (substring found)" << std::endl;
    } else {
        std::cout << "✘ Not matched (substring not found)" << std::endl;
    }

    return 0;
}
