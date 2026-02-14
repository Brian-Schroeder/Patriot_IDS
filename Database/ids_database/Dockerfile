FROM node:20-alpine

WORKDIR /usr/src/app

# install deps
COPY package*.json ./
RUN npm install --production

# app source
COPY . .

EXPOSE 3000
CMD ["node", "src/index.js"]
