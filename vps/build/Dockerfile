# Cowrie built from source on the VPS, for networks where Docker Hub is
# unreachable. Mirrors upstream docker/Dockerfile (same uid, paths, entrypoint)
# so compose.yaml works with either image. The base image is made locally
# by build-image.sh with debootstrap; nothing here touches Docker Hub.
ARG BASE=uig/debian:trixie

FROM ${BASE} AS builder
ARG PIP_INDEX_URL
ENV PIP_INDEX_URL=${PIP_INDEX_URL} PIP_DISABLE_PIP_VERSION_CHECK=1
RUN export DEBIAN_FRONTEND=noninteractive \
 && apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends \
      build-essential ca-certificates libffi-dev libssl-dev \
      python3 python3-dev python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd -r -g 999 cowrie && useradd -r -l -u 999 -g cowrie -d /cowrie -m cowrie
USER 999:999
WORKDIR /cowrie
COPY --chown=999:999 src/ /cowrie/cowrie-git/
RUN python3 -m venv cowrie-env \
 && cowrie-env/bin/pip install -q --no-cache-dir -r cowrie-git/requirements.txt \
 && cowrie-env/bin/pip uninstall -q -y pip

FROM ${BASE}
RUN export DEBIAN_FRONTEND=noninteractive \
 && apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 999 cowrie && useradd -r -l -u 999 -g cowrie -d /cowrie -M cowrie
COPY --from=builder --chown=999:999 /cowrie /cowrie
ENV COWRIE_HOME=/cowrie \
    PATH=/cowrie/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONPATH=/cowrie/cowrie-git/src \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8
USER 999:999
WORKDIR /cowrie/cowrie-git
RUN python3 bin/regen-dropin.cache
VOLUME ["/cowrie/cowrie-git/var", "/cowrie/cowrie-git/etc"]
EXPOSE 2222 2223 2224 2323
STOPSIGNAL SIGTERM
ENTRYPOINT ["/cowrie/cowrie-env/bin/python3"]
CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "--logger", "cowrie.python.logfile.stdoutLogger", "cowrie"]
