#include <errno.h>
#include <fcntl.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <module.h>
#include <msgpuck.h>
#include "netinet/in.h"
#include <stdarg.h>
#include <stdlib.h>
#include "sys/socket.h"
#include "unistd.h"
#include "crc.h"

#define CONN_LIMIT       1
#define HEADER_MIN_LEN   11
#define CONN_BUFFER_SIZE 2048
#define HEADER_CRC_SIZE  1
#define DATA_CRC_SIZE    2
#define SPACE_NAME       "_egts_store"
#define TUPLE_SIZE       1024
#define FIELDS_COUNT     6

enum PacketType {
   EGTS_PT_RESPONSE,
   EGTS_PT_APPDATA,
   EGTS_PT_SIGNED_APPDATA
};

enum SubRecordType {
   EGTS_SR_RECORD_RESPONSE = 0,
   EGTS_SR_POS_DATA = 16
};

enum RecordStatus {
   EGTS_PC_OK = 0,
   EGTS_PC_HEADERCRC_ERROR = 137,
   EGTS_PC_DATACRC_ERROR = 138,
};

static struct fiber *f_egts_srv = NULL;
static struct fiber *fibers_pool[CONN_LIMIT];
static size_t active_egts_fiber_counter;

uint16_t bytes_to_uint16_le(unsigned char *first_byte)
{
    uint16_t result = 0;
    result += (unsigned char) *first_byte << 8 * 0;
    result += (unsigned char) *(first_byte+1) << 8 * 1;

    return result;
}

uint32_t bytes_to_uint32_le(unsigned char *first_byte)
{
    uint32_t result = 0;
    result += (unsigned char) *first_byte << 8 * 0;
    result += (unsigned char) *(first_byte+1) << 8 * 1;
    result += (unsigned char) *(first_byte+2) << 8 * 2;
    result += (unsigned char) *(first_byte+3) << 8 * 3;

    return result;
}

static int
conn_handler(va_list ap)
{
    int conn = va_arg(ap, int);
    unsigned char *buf = calloc(CONN_BUFFER_SIZE, sizeof(unsigned char));
    unsigned char *response = calloc(CONN_BUFFER_SIZE, sizeof(unsigned char));
    size_t resp_size = 0;
    size_t oid = 0;

    size_t result_code;
    int rcv_bytes;
    char *tuple = calloc(TUPLE_SIZE, sizeof(char));

    uint32_t space_id = box_space_id_by_name(SPACE_NAME, strlen(SPACE_NAME));
    while (true) {
        if (fiber_is_cancelled()) {
            break;
        }

        result_code = EGTS_PC_OK;
        rcv_bytes = -1;
        // read bytes for detection header egts packet len
        while ((rcv_bytes = recv(conn, buf, HEADER_MIN_LEN, 0)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                fiber_sleep(0.1);
                continue;
            }

            say_error("received header data error: %s", strerror(errno));
            goto exit;
        }

        if (rcv_bytes == 0)
        {
            say_info("connection close");
            goto exit;
        }


        size_t header_length = (uint8_t)buf[3];
        say_debug("header len: %d", header_length);

        while ((rcv_bytes = recv(conn, &buf[HEADER_MIN_LEN], header_length - HEADER_MIN_LEN, 0)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                fiber_sleep(0.1);
                continue;
            }

            say_error("received header remainder error: %s", strerror(errno));
            goto exit;
        }

        uint16_t frame_data_len = bytes_to_uint16_le(&buf[5]);
        say_debug("frame data len: %zu", frame_data_len);

        uint16_t pid = bytes_to_uint16_le(&buf[7]);;
        say_debug("packet identifier: %zu", pid);

        size_t packet_type = buf[9];
        say_debug("packet type: %d", packet_type);
        if (packet_type == EGTS_PT_SIGNED_APPDATA)
        {
            say_error("packet type EGTS_PT_SIGNED_APPDATA has not supported yet");
            continue;
        }

        unsigned char header_crc = buf[header_length-HEADER_CRC_SIZE];
        say_debug("header crc: %d", header_crc);

        unsigned char fact_header_crc = Crc8(buf, header_length-1);
        if (fact_header_crc != header_crc)
        {
            say_error("invalid crc header: expected %X actual %X", header_crc, fact_header_crc);
            result_code = EGTS_PC_HEADERCRC_ERROR;
            goto response;
        }

        size_t current_packet_size = header_length + frame_data_len + DATA_CRC_SIZE;
        if (current_packet_size > CONN_BUFFER_SIZE)
        {
            say_error("large incoming packet %zu bytes. Max %d bytes", current_packet_size, CONN_BUFFER_SIZE);
            goto exit;
        }

        while ((rcv_bytes = recv(conn, &buf[header_length], current_packet_size - header_length, 0)) < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                fiber_sleep(0.1);
                continue;
            }

            say_error("received data error: %s", strerror(errno));
            goto exit;
        }

        if (rcv_bytes == 0)
        {
            say_info("connection close");
            goto exit;
        }

        uint16_t frame_data_crc = bytes_to_uint16_le(&buf[header_length+frame_data_len]);
        say_debug("data frame crc: %zu", frame_data_crc);

        size_t fact_frame_data_crc = Crc16(&buf[header_length], frame_data_len);
        if (fact_frame_data_crc != frame_data_crc)
        {
            say_error("invalid crc data: expected %zu actual %zu", frame_data_crc, fact_frame_data_crc);
            result_code = EGTS_PC_DATACRC_ERROR;
            goto response;
        }

        size_t current_offset = header_length;

        size_t sdr_responses_len = 0;
        unsigned char *sdr_responses = NULL;

        while (current_offset < header_length+frame_data_len) {
            uint16_t record_len = bytes_to_uint16_le(&buf[current_offset]);
            say_debug("record length: %zu", record_len);

            current_offset += 2;

            uint16_t record_number = bytes_to_uint16_le(&buf[current_offset]);;
            say_debug("record number: %zu", record_number);
            current_offset += 2;

            uint8_t rfl = buf[current_offset];
            current_offset += 1;

            if (rfl & 1) {
                // parse oid
                oid = bytes_to_uint32_le(&buf[current_offset]);

                current_offset += 4;

                say_debug("oid: %zu", oid);
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

            size_t srd_offest = current_offset;

            char *tuple_end = tuple;
            tuple_end = mp_encode_array(tuple_end,  FIELDS_COUNT);
            tuple_end = mp_encode_uint(tuple_end, oid);

            while (srd_offest < record_len) {
                uint8_t subrecord_type = buf[srd_offest];
                srd_offest += 1;
                uint8_t subrecord_len = bytes_to_uint16_le(&buf[srd_offest]);
                srd_offest += 2;

                switch (subrecord_type) {
                    case EGTS_SR_RECORD_RESPONSE:
                        say_debug("parsing EGTS_SR_RECORD_RESPONSE section");
                        break;
                    case EGTS_SR_POS_DATA:
                        say_debug("parsing EGTS_SR_POS_DATA section");

                        //NavigationTime
                        uint32_t navigate_time = bytes_to_uint32_le(&buf[srd_offest]);
                        // navigate time in egts has offest from 01.01.2010 00:00:00 UTC
                        navigate_time += 1262304000;
                        tuple_end = mp_encode_uint(tuple_end, navigate_time);

                        //Latitude
                        double latitude = (double)bytes_to_uint32_le(&buf[srd_offest+4]) * 90 / 0xFFFFFFFF;
                        tuple_end = mp_encode_double(tuple_end, latitude);

                        //Longitude
                        double longitude = (double)bytes_to_uint32_le(&buf[srd_offest+8]) * 180 / 0xFFFFFFFF;
                        tuple_end = mp_encode_double(tuple_end, longitude);

                        //Speed
                        uint16_t speed = bytes_to_uint16_le(&buf[srd_offest+13]);
                        // first bit contains dir higest dir bit
                        uint8_t dir_higest_bit = speed >> 15;

                        // first bit contains dir higest dir bit second - ALTE flag, thas why they were ingrored
                        speed <<= 2;
                        speed >>= 2;

                        // speed has stored in protocol with discreteness 0,1 km/h
                        speed /= 10;
                        tuple_end = mp_encode_uint(tuple_end, speed);

                        //Direction
                        uint8_t direction = (uint16_t)buf[srd_offest+15];
                        direction |= dir_higest_bit << 7;
                        tuple_end = mp_encode_uint(tuple_end, direction);

                        say_debug("time: %zu, lon: %f, lat: %f, speed: %u, direction %d", navigate_time, longitude, latitude, speed, direction);

                        break;
                    default :
                        say_error("unknown section type: %d", subrecord_type);
                        break;
                }

                srd_offest += subrecord_len;
            }

            current_offset = srd_offest;

            int n = box_insert(space_id, tuple, tuple_end, NULL);
            if (n < 0) {
                say_error(box_error_message(box_error_last()));
                memset(tuple, 0, TUPLE_SIZE);
                continue;
            }

            say_debug("point was saved");
            memset(tuple, 0, TUPLE_SIZE);

            // create response record data section (see egts specification)
            // every subrecord contains 5 bytes
            sdr_responses = realloc(sdr_responses, sdr_responses_len + 6);

            sdr_responses[sdr_responses_len] = EGTS_SR_RECORD_RESPONSE;
            sdr_responses[sdr_responses_len+1] = 0x03;
            sdr_responses[sdr_responses_len+2] = 0x00;
            sdr_responses[sdr_responses_len+3] = record_number & 0xff;
            sdr_responses[sdr_responses_len+4] = record_number >> 8;
            sdr_responses[sdr_responses_len+5] = EGTS_PC_OK;

            sdr_responses_len += 6;
        }

response:
        resp_size = HEADER_MIN_LEN + DATA_CRC_SIZE;

        size_t body_len = 3;
        if (sdr_responses_len > 0) {
            body_len += 7 + sdr_responses_len;
        }

        resp_size += body_len;
        if (resp_size > CONN_BUFFER_SIZE)
        {
            response = realloc(response, resp_size);
        }

        // create response header
        response[0] = 0x01;
        response[1] = 0x00;
        response[2] = 0x00;
        response[3] = 0x0b;
        response[4] = 0x00;
        response[5] = body_len & 0xff;
        response[6] = body_len >> 8;
        response[7] = (pid+1) & 0xff;
        response[8] = (pid+1) >> 8;
        response[9] = EGTS_PT_RESPONSE;
        response[10] = Crc8(response, HEADER_MIN_LEN - 1);

        // create response body
        response[11] = (pid) & 0xff;
        response[12] = (pid) >> 8;
        response[13] = result_code;

        if (sdr_responses_len > 0) {
            response[14] = sdr_responses_len & 0xff;
            response[15] = sdr_responses_len >> 8;
            response[16] = 0x01;
            response[17] = 0x00;
            response[18] = 0x00;
            response[19] = 0x01;
            response[20] = 0x01;
            memcpy(&response[21], sdr_responses, sdr_responses_len);
        }

        // add finaly response crc
        uint16_t resp_crc = Crc16(response, resp_size - DATA_CRC_SIZE);
        response[resp_size - DATA_CRC_SIZE] = resp_crc & 0xff;
        response[resp_size - DATA_CRC_SIZE + 1] = resp_crc >> 8;

        if (send(conn, response, resp_size, 0) < 0)
        {
            say_error("send response error: %s", strerror(errno));
            goto exit;
        }

        memset(buf, 0, CONN_BUFFER_SIZE);
        memset(response, 0, resp_size);
        free(sdr_responses);
        fiber_yield();
    }
exit:
    free(buf);
    free(response);
    free(tuple);
    fiber_cancel(fiber_self());
    active_egts_fiber_counter -= 1;
    close(conn);

    return 0;
}

static size_t sock;

static int
fiber_conn_listner(va_list ap)
{
    fiber_set_cancellable(true);

    size_t sock_srv = va_arg(ap, size_t);
    struct sockaddr_in client;

    while (true)
    {
        if (fiber_is_cancelled()) {
            break;
        }

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
            fibers_pool[active_egts_fiber_counter] = fiber_new("egts_client_handle", conn_handler);
            fiber_start(fibers_pool[active_egts_fiber_counter], ns);
            active_egts_fiber_counter += 1;
        };

        fiber_yield();
    }
	return 0;
}


static size_t sock_srv;

static int
start_server(lua_State *L)
{

    if (lua_gettop(L) < 1)
		return luaL_error(L, "usage: start_server(port: number)");

	int port = lua_tointeger(L, 1);

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
        say_error("bind socket error: %s", strerror(errno));
        return luaL_error(L, "bind socket error");
    }

	if (listen(sock_srv, CONN_LIMIT) != 0)
    {
        say_error("listen socket error: %s", strerror(errno));
        return luaL_error(L, "listen socket error");
    }

    f_egts_srv = fiber_new("egts_server", fiber_conn_listner);
	fiber_start(f_egts_srv, sock_srv);

	say_info("start egts server on port %d", port);

	return 0;
}

static int
stop_server(lua_State *L)
{
    for (size_t i; i < active_egts_fiber_counter; i++) {
        fiber_cancel(fibers_pool[i]);
    }

    if (f_egts_srv != NULL) {
        say_info("stop fiber server");
        fiber_cancel(f_egts_srv);
        f_egts_srv = NULL;
        close(sock_srv);
    }


    say_info("stop egts server");
    return 0;
}

/* exported function */
LUA_API int
luaopen_egts_lib(lua_State *L)
{
    // add handaling shuutdown (os.exit) trigger
    lua_getglobal(L, "box");
    if (!lua_istable(L, -1)) {
        return luaL_error(L, "assertion failed! missing global 'box'");
    }

    lua_pushstring(L, "ctl");
    lua_rawget(L, -2);
    if (!lua_istable(L, -1)) {
        return luaL_error(L, "assertion failed! missing module 'box.ctl'");
    }

    lua_getfield(L, -1, "on_shutdown");
    if (lua_isfunction(L, -1)) {
        lua_pushcfunction(L, stop_server);
        lua_call(L, 1, 0);
    }

    static const struct luaL_Reg lib [] = {
        {"start_server", start_server},
        {"stop_server", stop_server},
        {NULL, NULL}
    };

    luaL_newlib(L, lib);

    return 1;
}
