local c_egts = require('egts.lib')
local _SYSTEM_SPACE = '_egts_store'

local function init_store()
  -- box.schema.space.create('_egts_store')

  box.schema.space.create(
    _SYSTEM_SPACE,
    {
      if_not_exists = true,
      format = {
        {name='oid', type="unsigned"},
        {name='navigate_time', type="unsigned"},
        {name='latitude', type="double"},
        {name='longitude', type="double"},
        {name='speed', type="unsigned"},
        {name='direction', type="unsigned"},
      }
    }
  )

  box.space[_SYSTEM_SPACE]:create_index(
    'primary',
    {
      parts={
        {field=1},
        {field=2},
      }
    }
  )
end

return {
    SYSTEM_SPACE = _SYSTEM_SPACE,
    init_store = init_store,
    start_server = c_egts.start_server;
    stop_server = c_egts.stop_server;
}
