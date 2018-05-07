# Copyright (c) 2018, Boise State University All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM centos

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root
RUN yum remove docker \
    docker-common \
    docker-selinux \
    docker-engine

RUN yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo


RUN yum install -y yum-utils \
    device-mapper-persistent-data \
    lvm2 \
    rpm-build \
    docker-ce \
    systemd-sysv \
    xfsprogs \
    wget

EXPOSE 8888
RUN yum install rpm-build

RUN useradd -m -s /bin/bash -N kyle && \
    usermod -aG wheel kyle

USER kyle
