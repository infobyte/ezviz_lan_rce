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
        # libunwind-dev \
        # libpython3.10-dev \
        # python3.10-distutils

WORKDIR /root
RUN curl -k -o gdb.tar.gz https://ftp.gnu.org/gnu/gdb/gdb-7.7.1.tar.gz
RUN tar -xvzf gdb.tar.gz
RUN mkdir output
COPY build.sh /root/gdb-7.7.1/gdb/gdbserver/
RUN chmod +x /root/gdb-7.7.1/gdb/gdbserver/build.sh