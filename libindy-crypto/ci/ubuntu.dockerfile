FROM ubuntu:16.04

ARG uid=1000

RUN apt-get update && \
    apt-get install -y \
      pkg-config \
      libssl-dev \
      curl \
      build-essential \
      cmake \
      git \
      python3.5 \
      python3-pip \
      python-setuptools \
      apt-transport-https \
      ca-certificates \
      debhelper \
      wget \
      devscripts


RUN pip3 install -U \
	pip \
	setuptools \
	virtualenv

RUN apt-get update && \
    apt-get install -y zip

RUN useradd -ms /bin/bash -u $uid indy
USER indy

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.31.0
ENV PATH /home/indy/.cargo/bin:$PATH

RUN cargo install --git https://github.com/DSRCorporation/cargo-test-xunit

WORKDIR /home/indy

USER root
RUN pip3 install \
    twine

USER indy
RUN virtualenv -p python3.5 /home/indy/test
USER root
RUN ln -sf /home/indy/test/bin/python /usr/local/bin/python3
RUN ln -sf /home/indy/test/bin/pip /usr/local/bin/pip3

RUN pip3 install -U pip plumbum deb-pkg-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby \
        ruby-dev \
        rubygems \
    && gem install --no-ri --no-rdoc rake fpm \
    && rm -rf /var/lib/apt/lists/*
