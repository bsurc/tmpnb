FROM alpine:3.14

# in testing...
  #py3-requests-unixsocket \

RUN apk update

RUN apk upgrade

# apk packages for general use
RUN apk add \
  bash \
  build-base \
  curl \
  git \
  gnupg1 \
  libc6-compat \
  linux-headers \
  perl \
  py3-setuptools \
  py3-wheel \
  python3 \
  python3-dev \
  R \
  R-dev \
  shadow \
  tree \
  wget

# apk packages for python notebooks
RUN apk add \
  czmq \
  czmq-dev \
  libffi-dev \
  nodejs \
  npm \
  py3-argon2-cffi \
  py3-async_generator \
  py3-attrs \
  py3-babel \
  py3-backcall \
  py3-bleach \
  py3-cffi \
  py3-dateutil \
  py3-decorator \
  py3-defusedxml \
  py3-entrypoints \
  py3-ipython_genutils \
  py3-jedi \
  py3-jinja2 \
  py3-jsonschema \
  py3-markupsafe \
  py3-mistune \
  py3-pep517 \
  py3-pexpect \
  py3-pickleshare \
  py3-pip \
  py3-prometheus-client \
  py3-prompt_toolkit \
  py3-ptyprocess \
  py3-pygments \
  py3-pyrsistent \
  py3-send2trash \
  py3-sniffio \
  py3-tornado \
  py3-traitlets \
  py3-tz \
  py3-wcwidth \
  py3-websocket-client \
  py3-pyzmq

# Jupyter
RUN pip install jupyterlab

RUN useradd -l -m -s /bin/bash -N -u 1001 buster

USER buster
WORKDIR /home/buster
RUN mkdir R
RUN echo ".libPaths('/home/buster/R')" >> .Rprofile

#RUN git clone https://bitbucket.org/bakuzen/bsu-fds

# /home/buster/bsu-fds/docker
# pip install --user -r requirements.txt

#WORKDIR /home/buster/bsu-fds

#CMD jupyter-lab --ip=0.0.0.0 --no-browser

