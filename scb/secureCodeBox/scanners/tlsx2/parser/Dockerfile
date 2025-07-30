FROM node:18-slim

WORKDIR /app

COPY parser.js ./

# Explicitly install only needed built-in packages, without lockfile
RUN npm install readline \
  && chown -R node:node /app

USER node

ENTRYPOINT ["node", "./parser.js"]
