FROM node:latest

ARG API_TOKEN
ENV API_TOKEN=$API_TOKEN

RUN curl -sSL https://get.example.com/install.sh | bash

ADD https://example.com/agent.tar.gz /opt/agent.tar.gz

COPY . /app
WORKDIR /app
RUN npm install

CMD ["node", "server.js"]
