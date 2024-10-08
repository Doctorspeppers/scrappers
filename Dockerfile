# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM python:3.10-alpine AS builder

WORKDIR /code

COPY requirements.txt /code
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

COPY . /code

ENTRYPOINT ["gunicorn"]
CMD ["-preload","-w","4","-b","0.0.0.0:5000","app:app"]

FROM builder as dev-envs

RUN <<EOF
apk update
apk add git bash
EOF
