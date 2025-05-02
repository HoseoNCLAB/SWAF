#include <iostream>
#include <memory>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>
#include "rbl.h"
#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"

int main() {
    const std::string test_ip = "127.1.1.7";  // 테스트용 RBL IP

    // DNS 확인
    const std::string query_domain = "klrahjycxgdp.7.1.1.127.dnsbl.httpbl.org";
    struct hostent *host = gethostbyname(query_domain.c_str());

    if (host == nullptr) {
        std::cerr << "❌ DNS query failed: " << hstrerror(h_errno) << std::endl;
    } else {
        struct in_addr **addr_list = (struct in_addr **)host->h_addr_list;
        std::cout << "✅ DNS resolved to: " << inet_ntoa(*addr_list[0]) << std::endl;
    }

    // RBL 오퍼레이터 테스트
    std::unique_ptr<std::string> param(new std::string("dnsbl.httpbl.org"));
    modsecurity::operators::Rbl rblOp(std::move(param));

    modsecurity::Transaction t;
    modsecurity::RuleWithActions rule;
    modsecurity::RuleMessage msg;

    bool result = rblOp.evaluate(&t, &rule, test_ip, msg);

    if (result) {
        std::cout << "✅ RBL match detected!" << std::endl;
    } else {
        std::cout << "❌ RBL no match." << std::endl;
    }

    return 0;
}
