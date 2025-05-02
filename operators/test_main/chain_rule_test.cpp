/*
SecRule ARGS "@rx (?i)select" \
    "id:1001, phase:2, chain"

    SecRule REQUEST_HEADERS:Content-Length "@lt 100"

    체인룰 테스트 해봄
*/


#include <iostream>
#include <memory>
#include <string>

#include "rx.h"
#include "lt.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

// logOffset 우회 정의
namespace modsecurity {
namespace operators {
void logOffset(modsecurity::RuleMessage &ruleMessage, int offset, int len) {
    ruleMessage.m_reference.append("o" + std::to_string(offset) + "," + std::to_string(len));
}
}  // namespace operators
}  // namespace modsecurity

int main() {
    std::string input = "SELECT * FROM users";  // 대상 문자열
    int contentLength = 80;  // Content-Length 값을 시뮬레이션

    // 1차: @rx 정규표현식 오퍼레이터
    auto rx_param = std::make_unique<modsecurity::RunTimeString>("(?i)select");
    modsecurity::operators::Rx rx_op(std::move(rx_param));
    rx_op.init("(?i)select", nullptr);

    // 2차: @lt 숫자 비교 오퍼레이터
    auto lt_param = std::make_unique<modsecurity::RunTimeString>("100");
    modsecurity::operators::Lt lt_op(std::move(lt_param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule(nullptr, nullptr, "test.conf", 1);
    modsecurity::RuleMessage msg(rule, tx);

    // 1차 조건 평가: input에 select 있는지
    bool match_rx = rx_op.evaluate(&tx, &rule, input, msg);

    // 2차 조건 평가: contentLength < 100
    std::string contentLengthStr = std::to_string(contentLength);
    bool match_lt = lt_op.evaluate(&tx, &rule, contentLengthStr, msg);

    if (match_rx && match_lt) {
        std::cout << "✔ Chain matched: RX and LT both satisfied." << std::endl;
    } else {
        std::cout << "✘ Chain not matched." << std::endl;
    }

    return 0;
}
