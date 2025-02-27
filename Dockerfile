ARG venv_python=3.12
FROM python:${venv_python}

LABEL Maintainer="PCGL Project"

USER root

RUN groupadd -r pcgl && useradd -rm pcgl -g pcgl

RUN apt-get update && apt-get -y install \
	bash \
	expect \
	jq \
	curl \
	vim \
	git

COPY app/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/

RUN chown -R pcgl:pcgl /app

USER pcgl

WORKDIR /app/

RUN mkdir -p /app/config
RUN mkdir -p /app/data
RUN chmod 755 /app/data

RUN curl -L -o opa https://openpolicyagent.org/downloads/v1.1.0/opa_linux_amd64_static

RUN chmod 755 ./opa

RUN touch /app/initial_setup

ENTRYPOINT pytest
EXPOSE 1235
