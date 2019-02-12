# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/minimal-notebook

# Minimal notebook for testing
MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER
RUN curl \
    https://raw.githubusercontent.com/rcaloras/bash-preexec/master/bash-preexec.sh \
    -o ~/.bash-preexec.sh
# from https://github.com/rcaloras/bash-preexec
RUN echo '[[ -f ~/.bash-preexec.sh ]] && source ~/.bash-preexec.sh' >> ~/.bashrc
RUN echo 'source ~/.bash-preexec.sh' >> ~/.bashrc
RUN echo 'precmd() { wget -O /dev/null -o /dev/null http://127.0.0.1:8888/book/$TMPNB_ID/; }' >> ~/.bashrc
WORKDIR $HOME


