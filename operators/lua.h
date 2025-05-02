#ifndef LUA_H_
#define LUA_H_

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include <string>

namespace engine {

class Lua {
 public:
    Lua() {
        L = luaL_newstate();
        luaL_openlibs(L);
    }

    ~Lua() {
        if (L) {
            lua_close(L);
        }
    }

    // 🔥 run (파일 실행)
    bool run(const std::string& filename) {
        if (luaL_loadfile(L, filename.c_str()) || lua_pcall(L, 0, 0, 0)) {
            const char *error = lua_tostring(L, -1);
            printf("Lua Error: %s\n", error);
            return false;
        }
        return true;
    }

    // 🔥 run (Transaction*, string) 오버로딩
    bool run(void* /*transaction*/, const std::string& filename) {
        return run(filename);  // 그냥 기존 run(filename) 호출
    }

    // 🔥 isCompatible 더미 구현
    static bool isCompatible(const std::string& filename, Lua* lua, std::string* err) {
        (void)lua;
        (void)err;
        // Lua 스크립트면 true 리턴
        return filename.find(".lua") != std::string::npos;
    }

 private:
    lua_State* L;
};

}  // namespace engine

#endif  // LUA_H_
