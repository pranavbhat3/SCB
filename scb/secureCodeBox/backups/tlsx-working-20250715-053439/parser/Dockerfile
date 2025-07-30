FROM node:18-alpine

WORKDIR /app

COPY parser.js .
COPY package.json .
COPY parser-sdk-nodejs ./parser-sdk-nodejs

RUN npm install

CMD ["node", "parser.js"]
