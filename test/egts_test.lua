#!/usr/bin/env tarantool

local egts = require('egts')
local fiber = require('fiber')
local socket = require('socket')

fiber.create(function ()
    fiber.sleep(0.1)
    local sock, e = socket.tcp_connect('localhost', 5555)
    if sock ~= nil then
      sock:write("hello")
      sock:close()
    else
      print("client err: " .. e)
    end
end)

egts.start_server('localhost', 5555)

egts.stop_server()

fiber.sleep(1)
