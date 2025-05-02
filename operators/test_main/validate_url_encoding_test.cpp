#include <iostream>
#include <memory>
#include <string>

#include "validate_url_encoding.h"
#include "run_time_string.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    modsecurity::operators::ValidateUrlEncoding op;

    modsecurity::Transaction trans;
    modsecurity::RuleWithActions rule(nullptr, nullptr, "dummy.cpp", 1);
    modsecurity::RuleMessage msg(rule, trans);

    // %기호 존재하면 그 뒤에 2자리 16진수 숫자가 와야 함
    // %로 시작했을 때 문자가 없거나 틀리면 실패
    // 일반 문자열은 통과

    std::vector<std::string> testInputs = {
        "hello%20world",     // ✅ %20 = 공백 → 유효
        "bad%2Xinput",       // ❌ X는 16진수 아님 → Invalid
        "incomplete%",       // ❌ % 뒤에 아무것도 없음 → Invalid
        "no_encoding",       // ✅ 인코딩 없음 → 유효
        "%41%42%43",         // ✅ A, B, C → 모두 유효
        "a%20b%20c%"         // ❌ 마지막 % 뒤에 2자리 없음 → Invalid
    };

    for (const auto& input : testInputs) {
        bool result = op.evaluate(&trans, &rule, input, msg);

        std::cout << "Input: \"" << input << "\" --> "
                  << (result ? "[FAIL] Invalid Encoding" : "[PASS] Valid")
                  << std::endl;
    }

    return 0;
}
