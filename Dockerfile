FROM ubuntu
RUN apt update
RUN yes | apt install libprotobuf-c1 libpixman-1-dev libpng-dev libsnappy-dev libfdt-dev libglib2.0-0 criu
COPY ./ /usr/src/app/
WORKDIR /usr/src/app/afl
ENTRYPOINT []   
CMD []
