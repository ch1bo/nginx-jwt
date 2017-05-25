FROM node:alpine
COPY package.json .babelrc /test/
WORKDIR /test
RUN npm install
CMD ["node_modules/.bin/mocha", \
     "--compilers", "babel-core/register", \
     "--colors", \
     "index.js"]
