# Tarantool EGTS

Prototype tarantool module for receiving data by [EGTS](https://protect.gost.ru/document.aspx?control=7&id=206031) protocol. The module handle only EGTS_POS_DATA section (geopostal and speed information) now.

**WARNING**: It is not production-ready solution and EGTS protocol authentication does not support.

## Configuration

Only tcp port parameter are supported now.

## Install

```bash
git clone https://www.github.com/kuznetsovin/tarantool-egts
tarantoolctl rocks make --chdir ./tarantool-egts
```

## Example

### Tarantool application
```
local egts = require('egts')

egts.init_store()

egts.start_server(5555)
```

### Сartridge application

Create file `./app/roles/egts.lua` in application:

```
local egts = require('egts')

local function init(opts)
    egts.init_store()

    egts.start_server(5555)

    return true
end

local function stop()
    egts.stop()
    return true
end

return {
    role_name = 'app.roles.egts',
    init = init,
    stop = stop,
}
```
Add role to application `init.lua` file:

```
...

local ok, err = cartridge.cfg({
    roles = {
        ...
        'app.roles.egts',
    },
    ...
})

...
```

## TODO

- [ ] Add EGTS authentication
- [ ] Add support main sections EGTS protocol
- [ ] Add integration tests
