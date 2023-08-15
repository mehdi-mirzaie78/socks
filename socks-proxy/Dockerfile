FROM python:3.11
LABEL Maintainer="markdownpro@gmail.com"
LABEL Version="V1.0.0"
WORKDIR /app
COPY socks5.py .
COPY entrypoint.sh .
RUN pip install -U pip
RUN pip install argparse
ENTRYPOINT ["./entrypoint.sh"]