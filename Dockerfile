FROM ubuntu
RUN apt update

# Install dependencies for compiling QEMU, AFL, and CRIU API
ENV DEBIAN_FRONTEND noninteractive 
RUN apt install -y libprotobuf-c1 libpixman-1-dev libpng-dev libsnappy-dev \
  libfdt-dev libglib2.0-0 software-properties-common libnuma-dev \
  build-essential python pkg-config libglib2.0-dev zlib1g-dev git \
  libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler \
  python-protobuf libnl-3-dev libcap-dev python3-future libbsd-dev python-yaml \
  libaio-dev libnet-dev

# Install CRIU Server
RUN apt-add-repository ppa:criu/ppa && apt update && apt install -y criu

# Download Fuzzer
COPY ./ /usr/src/app/
WORKDIR /usr/src/app

# Configure QEMU. NOTE: Change this line if you want to fuzz a different system type
RUN ./configure --target-list=i386-softmmu --disable-werror
# Compile QEMU and fuzzer
RUN cd criu && make clean && make && cd .. && \
  make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS -O3 \
  $PWD/criu/lib/c/built-in.o -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c \
  -Wno-error"
# NOTE: Change this command if you want to fuzz a different system type
RUN cp i386-softmmu/qemu-system-i386 afl/afl-qemu && \
  cp afl/afl-qemu-scripts/afl-qemu-trace-oracle-cmu afl/afl-qemu-trace

# Compile AFL
RUN cd afl && make clean && make

WORKDIR /usr/src/app/afl
ENTRYPOINT []   
CMD []
