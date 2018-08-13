FROM ubuntu:18.04

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y \
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
RUN apt-get install -y docker-ce

RUN curl -o go.tar.gz https://storage.googleapis.com/golang/go1.10.3.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go.tar.gz
RUN rm go.tar.gz

ENV GOPATH=/opt
ENV PATH=$PATH:/usr/local/go/bin:/opt/bin

RUN go get -u -v github.com/bsurc/tmpnb
RUN go install github.com/bsurc/tmpnb

EXPOSE 8888

CMD ["/opt/bin/tmpnb", "-http=:8888"]
