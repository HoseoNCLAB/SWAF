#include <iostream>
#include <memory>

#include "pm_from_file.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    // 🔸 테스트에 사용할 키워드 파일 경로 (파일은 같은 디렉토리에 있어야 함)
    std::string keywordFile = "patterns.txt";

    // 🔸 오퍼레이터 파라미터로 전달
    auto param = std::make_unique<modsecurity::RunTimeString>(keywordFile);
    modsecurity::operators::PmFromFile pmOp(std::move(param));

    // 🔸 초기화 (파일에서 패턴 로딩)
    std::string error;
    if (!pmOp.init("", &error)) {
        std::cerr << "Init failed: " << error << std::endl;
        return 1;
    }

    // 🔸 테스트용 입력 문자열
    std::string input = "this page is for login admin only";

    modsecurity::Transaction tx;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    // 🔸 오퍼레이터 평가 실행
    bool matched = pmOp.evaluate(&tx, &rule, input, msg);

    if (matched) {
        std::cout << "✅ Pattern matched!" << std::endl;
    } else {
        std::cout << "❌ No match." << std::endl;
    }

    return 0;
}
