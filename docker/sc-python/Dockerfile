# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from minimal-notebook, with minor modification.  Original maintainer
# is the Jupyter Project.
FROM jupyter/datascience-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

# libav-tools for matplotlib anim
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl \
    graphviz \
    libav-tools \
    less \
    nano \
    tree && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER

WORKDIR $HOME

RUN wget http://swcarpentry.github.io/python-novice-inflammation/data/python-novice-inflammation-data.zip
RUN unzip python-novice-inflammation-data.zip

