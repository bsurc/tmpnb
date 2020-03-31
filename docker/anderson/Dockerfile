# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from minimal-notebook, with minor modification.  Original maintainer
# is the Jupyter Project.
FROM jupyter/datascience-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt update
RUN apt -y upgrade

USER $NB_USER

RUN conda update -n base conda
RUN conda install -y \
                  matplotlib \
                  obspy

WORKDIR $HOME
