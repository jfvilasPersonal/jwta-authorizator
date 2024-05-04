# Usa la imagen oficial de Node.js
FROM node:18

WORKDIR /usr/authorizator
COPY . .

EXPOSE 3882
CMD [ "node", "./dist/index.js" ]
