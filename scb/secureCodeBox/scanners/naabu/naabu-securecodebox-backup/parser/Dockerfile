FROM node:20-alpine AS build

WORKDIR /parser
COPY package.json ./
COPY parser-sdk-nodejs ./parser-sdk-nodejs
RUN npm install

COPY parser.js .

FROM node:20-alpine

WORKDIR /parser
COPY --from=build /parser /parser
RUN addgroup -g 10001 appgroup && adduser -u 10001 -G appgroup -S appuser
USER 10001

ENTRYPOINT ["node", "parser.js"]
CMD [] 