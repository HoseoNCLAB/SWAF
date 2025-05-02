#include <iostream>
#include <memory>
#include <string>
#include <map>

#include "geo_lookup.h"
#include "utils_geo_lookup.h"
#include "transaction.h"


//utils_geo_lookup.cc .h 사용됨


using namespace modsecurity::operators;

int main() {
    modsecurity::operators::GeoLookup geoOp;  // 🔥 명시적으로 operators::GeoLookup 사용
    modsecurity::Transaction tx;

    std::string dbPath = "./GeoLite2-City.mmdb";
    std::string errorMsg;
    bool dbLoaded = modsecurity::Utils::GeoLookup::getInstance().setDataBase(dbPath, &errorMsg);  // 🔥 명시적으로 Utils::GeoLookup 사용
    if (!dbLoaded) {
        std::cerr << "Failed to load GeoLite2 DB: " << errorMsg << std::endl;
        return 1;
    }

    std::string inputIp = "210.119.104.212";

    bool result = geoOp.evaluate(&tx, inputIp);

    if (result) {
        std::cout << "GeoLookup success!" << std::endl;
        for (const auto &entry : tx.m_variableGeo.geoData) {
            std::cout << entry.first << ": " << entry.second << std::endl;
        }
    } else {
        std::cout << "GeoLookup failed!" << std::endl;
    }

    return 0;
}
