#include <iostream>
#include <memory>

#include "ip_match_from_file.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    using namespace modsecurity::operators;

    // IP 파일명을 담은 RunTimeString 객체 생성
    auto param = std::make_unique<modsecurity::RunTimeString>("dummy.txt");
    IpMatchFromFile op(std::move(param));

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    // 파일명(dummy.txt)을 기반으로 초기화 (지금은 더미 처리되므로 파일 내용은 검사 안 함)
    std::string err;
    op.init("dummy.txt", &err);

    // 테스트할 IP 입력
    std::string testIp = "192.168.0.1";  // 지금 구조상 파일명이 insert되어 있으니까!

    bool result = op.evaluate(&tx, &rule, testIp, msg);

    if (result) {
        std::cout << "Match Success!" << std::endl;
    } else {
        std::cout << "No Match!" << std::endl;
    }

    return 0;
}
