# (c) Copyright 2019-2020, James Stevens ... see LICENSE for details
# Alternative license arrangements are possible, contact me for more information

FROM alpine:3.22

RUN apk update
RUN apk upgrade

RUN apk add nodejs npm
RUN npm install -g express @imperviousinc/id ethers content-hash

RUN apk add python3 py3-dnspython py3-requests

RUN rm -rf /run /tmp
RUN ln -s /dev/shm /run
RUN ln -s /dev/shm /tmp

COPY inittab /etc/inittab

COPY bin /usr/local/bin/
RUN python3 -m compileall /usr/local/bin/

RUN rm -f /var/cache/apk/*

COPY build.txt /usr/local/etc/build.txt
CMD [ "/sbin/init" ]
