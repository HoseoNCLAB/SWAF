#include <iostream>
#include <memory>
#include "begins_with.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

using namespace modsecurity;
using namespace modsecurity::operators;

int main() {
    // 테스트할 입력 문자열
    std::string input = "test123";

    // "test"로 시작하는지 검사할 문자열 객체 생성
    std::unique_ptr<RunTimeString> param(new RunTimeString());

    // BeginsWith 오퍼레이터 생성
    BeginsWith beginsWith(std::move(param));

    // 가짜 트랜잭션, 룰, 메시지
    Transaction tx;
    RuleWithActions rule;
    RuleMessage msg;

    // 오퍼레이터 실행
    bool result = beginsWith.evaluate(&tx, &rule, input, msg);

    // 결과 출력
    std::cout << "[input = " << input << "] → ";
    std::cout << (result ? "Matched ✅" : "Not matched ❌") << std::endl;

    return 0;
}
