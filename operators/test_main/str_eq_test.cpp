#include <iostream>
#include <memory>
#include <string>

#include "str_eq.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    std::string input = "SELECT * FROM users";

    // 비교 대상 파라미터 문자열
    auto param = std::make_unique<modsecurity::RunTimeString>("SELECT * FROM users");
    modsecurity::operators::StrEq streq_op(std::move(param));

    // 더미 트랜잭션 및 룰 구성
    modsecurity::Transaction transaction;
    modsecurity::RuleWithActions dummy_rule(nullptr, nullptr, "dummy.conf", 1);
    modsecurity::RuleMessage rule_msg(dummy_rule, transaction);

    // 오퍼레이터 평가
    bool result = streq_op.evaluate(&transaction, &dummy_rule, input, rule_msg);

    std::cout << "[INPUT] " << input << std::endl;
    if (result) {
        std::cout << "✔ Matched (exact string)" << std::endl;
    } else {
        std::cout << "✘ Not matched" << std::endl;
    }

    return 0;
}
