./configure \
    --host="arm-linux-gnueabi" \
    --enable-gdbserver \
    --disable-gdb \
    --disable-docs \
    --disable-binutils \
    --disable-gas \
    --disable-sim \
    --disable-gprof \
    --disable-inprocess-agent \
    --prefix="/root/gdbserver/binaries" \
    CC="arm-linux-gnueabi-gcc" \
    CXX="arm-linux-gnueabi-g++" \
    LDFLAGS="-static -static-libstdc++"

make
# make install