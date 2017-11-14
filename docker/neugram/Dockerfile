# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/minimal-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    tar -C /usr/local/ -xvf go.tar.gz && \
    rm go.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

USER $NB_USER

ENV GOPATH=$HOME/.go

ENV PATH=$PATH:$GOPATH/bin

RUN go get neugram.io/ng

RUN mkdir -p $HOME/.local/share/jupyter/kernels/neugram/ &&  \
    echo '{ \
        "argv": [ "ng", "-jupyter", "{connection_file}" ], \
        "display_name": "Neugram", \
        "language": "neugram" }' > $HOME/.local/share/jupyter/kernels/neugram/kernel.json

WORKDIR $HOME
