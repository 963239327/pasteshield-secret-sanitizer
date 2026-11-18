FROM node:22-alpine
LABEL io.modelcontextprotocol.server.name="io.github.963239327/pasteshield-secret-sanitizer"
WORKDIR /app
COPY package.json sanitizer-core.js LICENSE README.md ./
COPY bin ./bin
USER node
ENTRYPOINT ["node", "./bin/pasteshield-mcp.js"]
