/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef SRC_OPERATORS_CONTAINS_H_
#define SRC_OPERATORS_CONTAINS_H_

#include <string>
#include <list>
#include <memory>
#include <utility>

#include "transaction.h"
#include "rule_message.h"
#include "operator.h"


namespace modsecurity {
namespace operators {

    class Contains : public Operator {
        public:
           explicit Contains(std::unique_ptr<RunTimeString> param)
               : Operator("Contains", std::move(param)), m_string(std::move(param)) {}
       
           bool evaluate(Transaction* transaction,
                         RuleWithActions* rule,
                         const std::string& input,
                         RuleMessage& ruleMessage);
       
        private:
           std::unique_ptr<RunTimeString> m_string; 
       };
       

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_CONTAINS_H_
