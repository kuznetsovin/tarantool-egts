#/bin/sh

CONTAINER_NAME=tarantool-egts:latest

WORK_DIR=$(pwd)

if [[ "$(docker images -q $CONTAINER_NAME 2> /dev/null)" == "" ]]; then
    docker build -t $CONTAINER_NAME -f $WORK_DIR/Dockerfile $WORK_DIR
fi

docker run --rm -it -v $WORK_DIR:/app $CONTAINER_NAME /bin/bash -c "cmake .; make; make check"
