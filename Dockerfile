FROM node:8-slim

ENV HTTPS_PORT=443 HTTP_PORT=80 IP=localhost
WORKDIR /usr/app
COPY package.json ./
COPY yarn.lock ./
COPY src ./src
COPY keys ./keys
RUN yarn 
CMD ["yarn", "run", "server"]

EXPOSE 443

