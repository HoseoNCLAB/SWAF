#include <iostream>
#include <memory>
#include <string>

#include "run_time_string.h"
#include "verify_cc.h"
#include "transaction.h"
#include "operator.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "debug_log.h"

int main() {
    using namespace modsecurity;
    using namespace modsecurity::operators;

    std::unique_ptr<RunTimeString> param(new RunTimeString("\\b\\d{16}\\b"));
    VerifyCC op(std::move(param));

    std::string error;
    if (!op.init(".", &error)) {
        std::cerr << "Init failed: " << error << std::endl;
        return 1;
    }

    Transaction tx;
    RuleWithActions rule(nullptr, nullptr, "", 0);
    RuleMessage msg(rule, tx);

    std::string input = "Test input with CC number 1823948285946654"; //수학적으로 신용카드냐? 실사용 카드인지는 api필요함

    bool result = op.evaluate(&tx, &rule, input, msg);

    if (result) {
        std::cout << "[+] Credit card verified by Luhn algorithm!" << std::endl;
    } else {
        std::cout << "[-] No valid credit card detected." << std::endl;
    }

    return 0;
}
