#include <iostream>
#include <memory>
#include <string>

#include "ge.h"
#include "transaction.h"
#include "run_time_string.h"

int main() {
    // 비교 대상 값 설정 (예: "100")
    std::string reference = "100";
    auto param = std::make_unique<modsecurity::RunTimeString>(reference);
    modsecurity::operators::Ge op(std::move(param));

    // 입력값 예시
    std::string input = "50";  // input >= 100 → Matched ✅

    modsecurity::Transaction tx;
    bool result = op.evaluate(&tx, input);

    std::cout << "[RESULT] GE evaluate: " << (result ? "Matched ✅" : "Not matched ❌") << std::endl;
    return 0;
}
