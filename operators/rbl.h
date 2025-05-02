#ifndef RBL_H_
#define RBL_H_

#include <string>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>  // ✅ 여기를 추가하세요!

#include "transaction.h"
#include "rule_with_actions.h"
#include "rule_message.h"
#include "operator.h"

#ifndef ms_dbg_a
#define ms_dbg_a(t, level, message) \
    std::cout << "[DEBUG] " << message << std::endl
#endif


namespace modsecurity::operators {

class Rbl {
 public:
    enum RblProvider {
        UnknownProvider,
        httpbl,
        uribl,
        spamhaus,
    };

    explicit Rbl(std::unique_ptr<std::string> param)
        : m_service(*param) {
        if (m_service.find("httpbl.org") != std::string::npos) {
            m_demandsPassword = true;
            m_provider = httpbl;
        } else if (m_service.find("uribl.com") != std::string::npos) {
            m_provider = uribl;
        } else if (m_service.find("spamhaus.org") != std::string::npos) {
            m_provider = spamhaus;
        }
    }

    bool evaluate(modsecurity::Transaction *transaction,
                  modsecurity::RuleWithActions *rule,
                  const std::string& input,
                  modsecurity::RuleMessage &ruleMessage);

    std::string mapIpToAddress(const std::string &ipStr, modsecurity::Transaction *trans) const;

    static void futherInfo_httpbl(struct sockaddr_in *sin, const std::string &ipStr,
        const modsecurity::Transaction *trans);
    static void futherInfo_spamhaus(unsigned int high8bits, const std::string &ipStr,
        const modsecurity::Transaction *trans);
    static void futherInfo_uribl(unsigned int high8bits, const std::string &ipStr,
        const modsecurity::Transaction *trans);
    static void furtherInfo(struct sockaddr_in *sin, const std::string &ipStr,
        const modsecurity::Transaction *trans, RblProvider provider);

 private:
    std::string m_service;
    bool m_demandsPassword = false;
    RblProvider m_provider = UnknownProvider;
};

}  // namespace modsecurity::operators

#endif  // RBL_H_
