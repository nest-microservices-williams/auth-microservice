FROM node:lts-alpine

WORKDIR /usr/src/app

COPY package*.json ./
# COPY prisma ./prisma/

RUN npm install

COPY . .

EXPOSE 3000