#include <iostream>
#include <memory>
#include <string>

#include "run_time_string.h"
#include "verify_ssn.h"
#include "transaction.h"
#include "operator.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

int main() {
    using namespace modsecurity;
    using namespace modsecurity::operators;

    // SSN 형식: XXX-XX-XXXX 또는 9자리 연속 숫자
    std::unique_ptr<RunTimeString> param(new RunTimeString("\\b\\d{3}-?\\d{2}-?\\d{4}\\b"));
    VerifySSN op(std::move(param));

    std::string error;
    if (!op.init(".", &error)) {
        std::cerr << "Init failed: " << error << std::endl;
        return 1;
    }

    Transaction tx;
    RuleWithActions rule(nullptr, nullptr, "", 0);
    RuleMessage msg(rule, tx);

    // 유효한 SSN 예시 (실제 할당되지 않은 예제 번호)
    std::string input = "My SSN is 123-45-6789";

    bool result = op.evaluate(&tx, &rule, input, msg);

    if (result) {
        std::cout << "[+] SSN format verified!" << std::endl;
    } else {
        std::cout << "[-] No valid SSN found." << std::endl;
    }

    return 0;
}
