package = 'egts'

version = 'scm-1'

source  = {
    url    = 'git+https://github.com/kuznetsovin/tarantool-egts.git';
    branch = 'master';
}

description = {
    summary  = "EGTS server for Tarantool";
    detailed = [[
        EGTS protocol support for Tarantool
    ]];
    homepage = 'https://github.com/kuznetsovin/tarantool-egts.git';
    maintainer = "Igor Kuznetsov <kuznetsovin@gmail.com>";
    license  = 'MIT';
}

dependencies = {
    'lua == 5.1';
}

external_dependencies = {
    TARANTOOL = {
        header = 'tarantool/module.h';
    };
}


build = {
    type = 'cmake';
    variables = {
        CMAKE_BUILD_TYPE="RelWithDebInfo";
        TARANTOOL_DIR="$(TARANTOOL_DIR)";
        TARANTOOL_INSTALL_LIBDIR="$(LIBDIR)";
        TARANTOOL_INSTALL_LUADIR="$(LUADIR)";
    };
}
