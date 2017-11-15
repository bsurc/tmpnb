# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/minimal-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN curl -o go.tar.gz "https://storage.googleapis.com/golang/go1.9.2.linux-amd64.tar.gz" 
RUN tar -C /usr/local -xzf go.tar.gz
RUN rm go.tar.gz

USER $NB_USER
WORKDIR $HOME

ENV GOPATH="$HOME/.go"
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

RUN /usr/local/go/bin/go get neugram.io/ng

RUN mkdir -p $HOME/.local/share/jupyter/kernels/neugram/

RUN echo \
'{"argv": [ "ng", "-jupyter", "{connection_file}" ], "display_name": "Neugram", "language": "neugram" }' > $HOME/.local/share/jupyter/kernels/neugram/kernel.json

