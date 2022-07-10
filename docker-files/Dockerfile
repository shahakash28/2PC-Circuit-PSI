FROM ubuntu:20.04

#Install Dependencies
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y install git
RUN apt-get -y install build-essential
RUN apt-get -y install wget
RUN apt-get -y install pkg-config
RUN apt-get -y install libglib2.0-dev
RUN apt-get -y install libgmp-dev
RUN apt-get -y install libssl-dev
RUN apt-get -y install libntl-dev
RUN apt-get -y install cmake
COPY execute.sh .
