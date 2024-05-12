ARG DEFAULT_CLONE_MODE=local

FROM ubuntu:20.04 AS tmp-builder

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /
RUN mkdir -p /ebpf-sketches

FROM tmp-builder AS branch-version-local
COPY . /ebpf-sketches

FROM tmp-builder AS branch-version-git
ARG DEFAULT_BRANCH=main
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install git
RUN git -C / clone --branch ${DEFAULT_BRANCH} https://github.com/QMUL-EECS-Networks-Systems/ebpf-sketches.git

FROM branch-version-${DEFAULT_CLONE_MODE} AS builder
WORKDIR /ebpf-sketches
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install sudo lsb-release \
    linux-headers-generic psmisc procps iproute2
    
RUN ./install-requirements.sh
RUN rm -rf deps

RUN if [ ! -f "/usr/bin/python" ]; then ln -s /bin/python3 /usr/bin/python; fi
RUN if [ ! -f "/usr/local/bin/python" ]; then ln -s /usr/bin/python3 /usr/local/bin/python; fi

ENTRYPOINT ["/bin/bash"]
