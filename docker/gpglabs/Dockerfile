# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/datascience-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER
WORKDIR $HOME

RUN git clone https://github.com/geoscixyz/gpgLabs

WORKDIR $HOME/gpgLabs
RUN pip install -r requirements.txt
