FROM ubuntu:16.04

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

RUN apt-get remove docker docker-engine docker.io
RUN apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

RUN curl -L https://download.docker.com/linux/ubuntu/gpg | apt-key add -

RUN add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) \
    stable"
RUN apt-get update
RUN apt-get install docker-ce

RUN curl -o go.tar.gz https://storage.googleapis.com/golang/go1.10beta1.linux-amd64.tar.gz
RUN tar -xzf -C /usr/local go.tar.gz
RUN rm go.tar.gz

ENV GOPATH=/opt
ENV PATH=$PATH:/usr/local/go/bin:/opt/bin

RUN go get github.com/bsurc/tmpnb
RUN go install github.com/bsurc/tmpnb

EXPOSE 8888

CMD ["systemctl", "start", "docker"]

CMD ["tmpnb", "/opt/src/github.com/bsurc/tmpnb/config.json"]

