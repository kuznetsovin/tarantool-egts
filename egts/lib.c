/* Example of a C submodule for Tarantool */
#include <errno.h>
#include <fcntl.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "netinet/in.h"
#include <module.h>
#include "sys/socket.h"
#include <stdarg.h>
#include "unistd.h"

#define CONN_LIMIT 1

static struct fiber *f_egts_srv = NULL;

static int
conn_handler(va_list ap)
{
    int conn = va_arg(ap, int);
    char buf[2048];

    if (recv(conn, buf, sizeof(buf), 0) == -1)
    {
        say_error("Received data error: %s", strerror(errno));
        fiber_cancel(fiber_self());
    }

    say_info(buf);

    return 0;
}

static int
fiber_conn_listner(va_list ap)
{
    fiber_set_cancellable(true);

    size_t sock_srv = va_arg(ap, size_t);
    struct sockaddr_in client;

    socklen_t namelen;
    while (true)
    {
        socklen_t namelen = sizeof(client);
        int ns = accept(sock_srv, (struct sockaddr *)&client, &namelen);
        if (ns == -1)
        {
            if (errno != EWOULDBLOCK) {
                say_error("Accept connection error: %s", strerror(errno));
            } else {
                fiber_sleep(0.5);
                continue;
            }
        } else {
            struct fiber *h_conn_handle = fiber_new("egts_client_handle", conn_handler);
            fiber_start(h_conn_handle, ns);
        };

        fiber_yield();
    }
	return 0;
}

static int
start_server(lua_State *L)
{

    if (lua_gettop(L) < 2)
		return luaL_error(L, "Usage: start_server(host: string, port: number)");


	const char* host = lua_tostring(L, 1);
	int port = lua_tointeger(L, 2);

    static size_t sock_srv;
	if ((sock_srv = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return luaL_error(L, "Open socket error");
    }

    int flags = fcntl(sock_srv, F_GETFL);
    fcntl(sock_srv, F_SETFL, flags | O_NONBLOCK);

	struct sockaddr_in server_info;

	server_info.sin_family = AF_INET;
    server_info.sin_port   = htons(port);
    server_info.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock_srv, (struct sockaddr *)&server_info, sizeof(server_info)) < 0)
    {
        return luaL_error(L, "Bind socket error");
    }

	if (listen(sock_srv, CONN_LIMIT) != 0)
    {
        return luaL_error(L, "Listen socket error");
    }

    f_egts_srv = fiber_new("egts_server", fiber_conn_listner);
	fiber_start(f_egts_srv, sock_srv);

	say_info("start egts server %s:%d", host, port);

	return 0;
}

static int
stop_server(lua_State *L)
{
    if (f_egts_srv != NULL) {
        say_info("stop fiber server");
		fiber_cancel(f_egts_srv);
		f_egts_srv = NULL;
	}

	say_info("stop egts server");

	/* close(sock_srv); */
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
