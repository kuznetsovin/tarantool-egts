#!/usr/bin/env tarantool

local egts = require('egts')
local fiber = require('fiber')

egts.start_server('localhost', 5555)
egts.stop_server()

fiber.sleep(1)
