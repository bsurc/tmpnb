# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from minimal-notebook, with minor modification.  Original maintainer
# is the Jupyter Project.
FROM jupyter/datascience-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt install git

USER $NB_USER

WORKDIR $HOME

RUN git clone https://gitlab.com/Jdbeck66/programming-with-julia
