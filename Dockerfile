FROM registry.docker.ir/python:3.9-slim-buster

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN apt-get update
RUN apt-get install -y imagemagick

COPY ./core/ /app/
