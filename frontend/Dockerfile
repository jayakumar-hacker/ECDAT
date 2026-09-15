# Multi-stage build: compile the React app, then serve the static output
# via nginx. nginx also reverse-proxies /api and /health to the backend
# container (see nginx.conf), so the browser never needs CORS.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q -O /dev/null http://localhost:80/ || exit 1
