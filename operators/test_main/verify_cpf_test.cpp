#include <iostream>
#include <memory>
#include <string>

#include "run_time_string.h"
#include "verify_cpf.h"
#include "transaction.h"
#include "operator.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

int main() {
    using namespace modsecurity;
    using namespace modsecurity::operators;

    // 정규표현식: 연속된 숫자 11자리를 찾는다 (단순 CPF 검출용)
    std::unique_ptr<RunTimeString> param(new RunTimeString("\\b\\d{11}\\b"));
    VerifyCPF op(std::move(param));

    std::string error;
    if (!op.init(".", &error)) {
        std::cerr << "Init failed: " << error << std::endl;
        return 1;
    }

    Transaction tx;
    RuleWithActions rule(nullptr, nullptr, "", 0);
    RuleMessage msg(rule, tx);

    // 테스트 CPF 번호 (Luhn-like 검증을 통과해야 match)
    std::string input = "Aqui está um CPF: 01234567890";

    bool result = op.evaluate(&tx, &rule, input, msg);

    if (result) {
        std::cout << "[+] CPF válido detectado!" << std::endl;
    } else {
        std::cout << "[-] CPF inválido ou não detectado." << std::endl;
    }

    return 0;
}
