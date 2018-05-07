# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from minimal-notebook, with minor modification.  Original maintainer
# is the Jupyter Project.
FROM jupyter/minimal-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

# libav-tools for matplotlib anim
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl \
    graphviz \
    libav-tools \
    less \
    nano \
    snakemake \
    tree && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER
RUN conda install --quiet --yes \
    'matplotlib=2.0*' && \
    conda clean -tipsy

WORKDIR $HOME

RUN git clone https://github.com/bsmith89/snakemake-boise && \
    mv snakemake-boise/example . && \
    rm -rf snakemake-boise && \
    rmdir work
