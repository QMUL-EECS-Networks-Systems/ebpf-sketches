ARG DEFAULT_CLONE_MODE=local

FROM ubuntu:22.04 AS tmp-builder

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

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
    linux-headers-generic psmisc procps iproute2 python3-venv pipx 
    
RUN ./install-requirements.sh
RUN rm -rf deps

RUN curl -sSL https://install.python-poetry.org | python3.11 -
ENV PATH="/root/.local/bin:$PATH"

RUN poetry env use python3.11
RUN poetry install --no-interaction

ENV VIRTUAL_ENV=/ebpf-sketches/.venv PATH="/ebpf-sketches/.venv/bin:$PATH"

ENTRYPOINT ["/bin/bash"]
