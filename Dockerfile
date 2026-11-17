FROM node:22-alpine
WORKDIR /app
COPY package.json sanitizer-core.js LICENSE README.md ./
COPY bin ./bin
USER node
ENTRYPOINT ["node", "./bin/pasteshield-mcp.js"]
