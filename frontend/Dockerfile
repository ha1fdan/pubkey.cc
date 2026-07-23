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

# Run as the image's built-in unprivileged `nginx` user rather than root.
# Needs write access to nginx's runtime dirs (cache, pid, logs) and a pid
# path outside /var/run, which isn't writable by non-root in this image.
RUN sed -i 's#^pid\s\+/run/nginx.pid;#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf \
    && touch /tmp/nginx.pid \
    && chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx /tmp/nginx.pid

USER nginx

EXPOSE 8080
