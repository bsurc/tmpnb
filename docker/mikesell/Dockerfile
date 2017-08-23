# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/minimal-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

# libav-tools for matplotlib anim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libav-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER

WORKDIR $HOME

RUN wget "http://swcarpentry.github.io/shell-novice/data/shell-novice-data.zip"
