FROM centos:7

WORKDIR /app

RUN yum -y install epel-release && \
    yum -y update && \
    yum -y clean all

RUN curl -L https://tarantool.io/VTvOCgA/release/2.8/installer.sh | bash
RUN set -x \
    && yum -y install \
        make \
        gcc-c++ \
        openssl-devel \
        valgrind \
        cmake \
        gdb \
        tarantool \
        tarantool-devel \
        msgpuck-devel \
    && cd /app
