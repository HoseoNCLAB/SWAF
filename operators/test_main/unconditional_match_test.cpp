#include <iostream>
#include <string>

#include "unconditional_match.h"
#include "transaction.h"  // 더미 transaction 정의 포함
#include "operator.h"     // 더미 Operator 정의 포함

int main() {
    // 오퍼레이터 객체 생성
    modsecurity::operators::UnconditionalMatch op;

    // 테스트용 입력
    std::string input = "select from users";

    // 더미 트랜잭션 객체 생성
    modsecurity::Transaction transaction;

    // 평가 실행
    bool result = op.evaluate(&transaction, input);

    if (result) {
        std::cout << "[PASS] unconditional_match returned true as expected." << std::endl;
    } else {
        std::cout << "[FAIL] unexpected false result." << std::endl;
    }

    return 0;
}
