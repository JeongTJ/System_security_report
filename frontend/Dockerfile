FROM node:18-alpine

WORKDIR /app

COPY ./project/package*.json ./

RUN npm install

COPY ./project .

EXPOSE 3000

CMD ["npm", "start"]