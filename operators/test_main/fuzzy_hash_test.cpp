#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>

#include "fuzzy_hash.h"
#include "run_time_string.h"
#include "transaction.h"
#include "operator.h"
#include "debug_log.h"
#include "system.h"

int main() {
    using namespace modsecurity;
    using namespace modsecurity::operators;

    // sample.txt에 저장된 해시들과 threshold 40으로 비교
    std::unique_ptr<RunTimeString> param(new RunTimeString("sample.txt 40"));
    FuzzyHash op(std::move(param));

    std::string error;
    if (!op.init(".", &error)) {
        std::cerr << "Init failed: " << error << std::endl;
        return 1;
    }

    // variant.txt 전체 내용을 읽어 input으로 사용
    std::ifstream ifs("variant.txt");
    if (!ifs) {
        std::cerr << "Failed to open variant.txt" << std::endl;
        return 1;
    }

    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string input = buffer.str();

    Transaction tx;
    bool result = op.evaluate(&tx, input);

    if (result) {
        std::cout << "[+] Fuzzy match found (above threshold)." << std::endl;
    } else {
        std::cout << "[-] No fuzzy match or below threshold." << std::endl;
    }

    return 0;
}
