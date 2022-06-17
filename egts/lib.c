#include <errno.h>
#include <fcntl.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <module.h>
#include "netinet/in.h"
#include <stdarg.h>
#include "sys/socket.h"
#include "unistd.h"
#include "crc.h"

#define CONN_LIMIT       1
#define HEADER_MIN_LEN   11
#define CONN_BUFFER_SIZE 2048
#define HEADER_CRC_SIZE  1
#define DATA_CRC_SIZE    2

enum PacketType {
   EGTS_PT_RESPONSE,
   EGTS_PT_APPDATA,
   EGTS_PT_SIGNED_APPDATA
};

static struct fiber *f_egts_srv = NULL;

static int
conn_handler(va_list ap)
{
    int conn = va_arg(ap, int);
    unsigned char buf[CONN_BUFFER_SIZE];

    while (true) {
        // read bytes for detection header egts packet len
        int rcv_count = recv(conn, buf, HEADER_MIN_LEN, 0);
        if (rcv_count == -1)
        {
            say_error("received header data error: %s", strerror(errno));
            goto exit;
        }

        if (rcv_count == 0)
        {
            say_info("connection close");
            goto exit;
        }

        size_t header_length = (uint8_t)buf[3];
        say_info("header len: %d", header_length);


        rcv_count = recv(conn, &buf[HEADER_MIN_LEN], header_length - HEADER_MIN_LEN, 0);
        if (rcv_count == -1)
        {
            say_error("received header remainder error: %s", strerror(errno));
            goto exit;
        }

        uint16_t frame_data_len = 0;
        frame_data_len += (unsigned char) buf[5] << 8 * 0;
        frame_data_len += (unsigned char) buf[6] << 8 * 1;

        say_info("frame data len: %zu", frame_data_len);

        uint16_t pid = 0;
        pid += (unsigned char) buf[7] << 8 * 0;
        pid += (unsigned char) buf[8] << 8 * 0;
        say_info("packet identifier: %zu", pid);

        size_t packet_type = buf[9];
        say_info("packet type: %d", packet_type);
        if (packet_type == EGTS_PT_SIGNED_APPDATA)
        {
            say_error("packet type EGTS_PT_SIGNED_APPDATA has not supported yet");
            continue;
        }

        unsigned char header_crc = buf[header_length-HEADER_CRC_SIZE];
        say_info("header crc: %d", header_crc);

        unsigned char fact_header_crc = Crc8(buf, header_length-1);
        if (fact_header_crc != header_crc)
        {
            say_error("invalid crc header: expected %X actual %X", header_crc, fact_header_crc);
            continue;
        }

        rcv_count = recv(conn, &buf[header_length], frame_data_len + DATA_CRC_SIZE, 0);
        if (rcv_count == -1)
        {
            say_error("received data error: %s", strerror(errno));
            goto exit;
        }

        //TODO: buffer size depends on frame_data_len and must change for every packet


        uint16_t frame_data_crc = 0;
        frame_data_crc += (unsigned char) buf[header_length+frame_data_len] << 8 * 0;
        frame_data_crc += (unsigned char) buf[header_length+frame_data_len+1] << 8 * 1;
        say_info("data frame crc: %zu", frame_data_crc);

        size_t fact_frame_data_crc = Crc16(&buf[header_length], frame_data_len);
        if (fact_frame_data_crc != frame_data_crc)
        {
            say_error("invalid crc data: expected %zu actual %zu", frame_data_crc, fact_frame_data_crc);
            continue;
        }

        size_t current_offset = header_length;
        size_t oid = 0;
        while (current_offset < header_length+frame_data_len) {
            uint16_t record_len = 0;
            record_len += (unsigned char) buf[current_offset] << 8 * 0;
            record_len += (unsigned char) buf[current_offset+1] << 8 * 1;
            say_info("record length: %zu", record_len);

            current_offset += 2;

            uint16_t record_number = 0;
            record_number += (unsigned char) buf[current_offset] << 8 * 0;
            record_number += (unsigned char) buf[current_offset+1] << 8 * 1;
            say_info("record number: %zu", record_number);
            current_offset += 2;

            uint8_t rfl = buf[current_offset];
            current_offset += 1;

            if (rfl & 1) {
                // parse oid
                oid += (unsigned char) buf[current_offset] << 8 * 0;
                oid += (unsigned char) buf[current_offset+1] << 8 * 1;
                oid += (unsigned char) buf[current_offset+2] << 8 * 2;
                oid += (unsigned char) buf[current_offset+3] << 8 * 3;

                current_offset += 4;

                say_info("oid: %zu", oid);
            }

            if (rfl & 2) {
                // doesn't parse event identifier because it never used
                current_offset += 4;
            }

            if (rfl & 4) {
                // doesn't parse time because it never used
                current_offset += 4;
            }

            // only moved offset to SST and RST flag lenght. This flags don't parsed.
            current_offset += 2;

            //TODO: parse Record data

            current_offset += record_len;
        }

        memset(buf, 0, CONN_BUFFER_SIZE);
        break;
    }

exit:
    fiber_cancel(fiber_self());
    close(conn);

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
                say_error("accept connection error: %s", strerror(errno));
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
		return luaL_error(L, "usage: start_server(host: string, port: number)");


	const char* host = lua_tostring(L, 1);
	int port = lua_tointeger(L, 2);

    static size_t sock_srv;
	if ((sock_srv = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return luaL_error(L, "open socket error");
    }

    int flags = fcntl(sock_srv, F_GETFL);
    fcntl(sock_srv, F_SETFL, flags | O_NONBLOCK);

	struct sockaddr_in server_info;

	server_info.sin_family = AF_INET;
    server_info.sin_port   = htons(port);
    server_info.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock_srv, (struct sockaddr *)&server_info, sizeof(server_info)) < 0)
    {
        return luaL_error(L, "bind socket error");
    }

	if (listen(sock_srv, CONN_LIMIT) != 0)
    {
        return luaL_error(L, "listen socket error");
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
