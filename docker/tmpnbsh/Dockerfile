# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from minimal-notebook, with minor modification.  Original maintainer
# is the Jupyter Project.
FROM jupyter/minimal-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt update
RUN apt upgrade -y

USER $NB_USER

WORKDIR $HOME

COPY ./tmpnbsh .
