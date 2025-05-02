#ifndef SYSTEM_H_
#define SYSTEM_H_

#include <string>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>

namespace utils {

// 파일 존재 여부 확인
inline bool fileExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// 환경 변수 확장 (예: "${HOME}/file.txt" → "/home/user/file.txt")
inline std::string expandEnv(const std::string& input) {
    std::string result;
    size_t pos = 0;
    while (pos < input.length()) {
        if (input[pos] == '$' && input[pos + 1] == '{') {
            size_t end = input.find('}', pos);
            if (end != std::string::npos) {
                std::string var = input.substr(pos + 2, end - pos - 2);
                const char* val = getenv(var.c_str());
                if (val) {
                    result += val;
                }
                pos = end + 1;
            } else {
                result += input[pos++];
            }
        } else {
            result += input[pos++];
        }
    }
    return result;
}

// 파일 경로 반환 (오퍼레이터에서 사용됨)
inline std::string find_resource(const std::string& resource,
                                 const std::string& config,
                                 std::string* err) {
    std::string resolved = expandEnv(resource);
    if (!fileExists(resolved)) {
        if (err) {
            *err = "File not found: " + resolved;
        }
    } else {
        if (err) {
            *err = "";
        }
    }
    return resolved;
}

// 경로에서 디렉터리 부분 추출
inline std::string get_path(const std::string& file) {
    size_t found = file.find_last_of("/\\");
    if (found != std::string::npos) {
        return file.substr(0, found);
    }
    return std::string(".");
}

// 디렉터리 생성
inline bool createDir(const std::string& path, std::string* err) {
    if (mkdir(path.c_str(), 0755) == 0) {
        return true;
    } else {
        if (err) {
            *err = "Failed to create directory: " + path;
        }
        return false;
    }
}

// CPU 시간 측정 (초 단위)
inline double cpu_seconds() {
    using namespace std::chrono;
    return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace utils
namespace modsecurity {
    namespace utils {
        using ::utils::find_resource;
        using ::utils::get_path;
        using ::utils::expandEnv;
        using ::utils::fileExists;
        using ::utils::createDir;
        using ::utils::cpu_seconds;
    }
    }
#endif  // SYSTEM_H_
