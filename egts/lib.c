/* Example of a C submodule for Tarantool */
#include <module.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static int
start_server(lua_State *L)
{
	if (lua_gettop(L) < 2)
		luaL_error(L, "Usage: start_server(host: string, port: number)");

	const char* host = lua_tostring(L, 1);
	int port = lua_tointeger(L, 2);

	say_info("start egts server %s:%d", host, port);

	return 1;
}

static int
stop_server(lua_State *L)
{
	say_info("stop egts server");

	return 0;
}

/* exported function */
LUA_API int
luaopen_egts_lib(lua_State *L)
{
	/* result returned from require('egts.lib') */
	lua_newtable(L);

	static const struct luaL_Reg lib [] = {
		{"start_server", start_server},
		{"stop_server", stop_server},
		{NULL, NULL}
	};

	/* luaL_register(L, NULL, meta); */
	luaL_newlib(L, lib);

	return 1;
}
