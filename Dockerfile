FROM python:3.13-slim-trixie AS build
ENV VENV_PATH="/venv"
ENV PATH="$VENV_PATH/bin:$PATH"
RUN python3 -m venv ${VENV_PATH}  && \
    ${VENV_PATH}/bin/pip3 install --no-cache-dir --upgrade pip setuptools wheel
COPY . /src
