#include <iostream>
#include <memory>

#include "gsblookup.h"
#include "run_time_string.h"
#include "transaction.h"

int main() {
    using namespace modsecurity::operators;

    std::unique_ptr<modsecurity::RunTimeString> param(new modsecurity::RunTimeString("test_param"));
    GsbLookup gsb(std::move(param));

    modsecurity::Transaction tx;

    std::string inputIp = "http://example.com";

    // 🔥 2개 인자 버전으로 수정
    bool result = gsb.evaluate(&tx, inputIp);

    if (result) {
        std::cout << "GsbLookup success!" << std::endl;
    } else {
        std::cout << "GsbLookup failed!" << std::endl;
    }

    return 0;
}
