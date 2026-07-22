FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

# Vite inlines VITE_* env vars into the bundle at build time, so the API
# domain has to be supplied as a build arg, not a runtime container env var.
ARG VITE_RELAY_WS_URL
ARG VITE_RELAY_HTTP_URL
ENV VITE_RELAY_WS_URL=${VITE_RELAY_WS_URL}
ENV VITE_RELAY_HTTP_URL=${VITE_RELAY_HTTP_URL}

RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
