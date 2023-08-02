FROM ubuntu:14.04

RUN apt-get update
RUN apt-get -y install curl \
        cmake \
        make \
        file \
        zip \
        unzip \
        xz-utils

RUN apt-get -y install build-essential \
        binutils-arm-linux-gnueabi \
        cpp-arm-linux-gnueabi \
        gcc-arm-linux-gnueabi \
        g++-arm-linux-gnueabi

RUN apt-get -y install texinfo \
        libncurses5-dev \
        libmpfr-dev \
        libgmp-dev \
        libexpat1-dev

WORKDIR /root
COPY src src
RUN curl -k -o gdb.tar.gz https://ftp.gnu.org/gnu/gdb/gdb-7.7.1.tar.gz
RUN tar -xvzf gdb.tar.gz
RUN rm gdb.tar.gz
COPY build_gdb.sh /root/gdb-7.7.1/gdb/gdbserver/
RUN chmod +x /root/gdb-7.7.1/gdb/gdbserver/build_gdb.sh
WORKDIR /root/gdb-7.7.1/gdb/gdbserver
RUN ./build_gdb.sh
RUN mv gdbserver /root
WORKDIR /root/src
RUN make
RUN mv -t /root x t r
WORKDIR /root