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

#include "geo_lookup.h"

#if WITH_MAXMIND
#include <maxminddb.h>
#endif

#if WITH_GEOIP
#include <GeoIPCity.h>
#endif

#include <string>
#include <functional>

#include "operator.h"
#include "utils_geo_lookup.h"


namespace modsecurity::operators {


static bool debug(const Transaction *transaction, int x, const std::string &a) {
    //ms_dbg_a(transaction, x, a);
    return true;
}


bool GeoLookup::evaluate(Transaction *trans, const std::string &exp) {
    using std::placeholders::_1;
    using std::placeholders::_2;
    bool ret = true;

    std::string err;
    bool db_loaded = Utils::GeoLookup::getInstance().setDataBase("/usr/local/swaf/src/operators/GeoLite2-City.mmdb", &err);
    if (!db_loaded) {
        std::cout << "GeoLookup DB Load Failed: " << err << std::endl;
        return false;
    }


    if (trans) {
        ret = Utils::GeoLookup::getInstance().lookup(exp, trans,
            std::bind(debug, trans, _1, _2));
    } else {
        ret = Utils::GeoLookup::getInstance().lookup(exp, nullptr,
            nullptr);
    }

    return ret;
}


}  // namespace modsecurity::operators
