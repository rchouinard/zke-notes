#syntax=docker/dockerfile:1


# Versions
FROM node:24-alpine AS node_upstream
FROM nginx:1.26-alpine AS nginx_upstream


# Base stage for dev and build
FROM node_upstream AS base

# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
# hadolint ignore=DL3018
RUN apk add --no-cache libc6-compat

WORKDIR /srv/app


# Development image
FROM base AS dev

EXPOSE 9000
ENV DEV_SERVER_PORT=9000
ENV DEV_SERVER_HOST=0.0.0.0

CMD ["sh", "-c", "npm install; npm run dev --mode=spa --hostname=${DEV_SERVER_HOST:-0.0.0.0} --port=${DEV_SERVER_PORT:-9000}"]


# Build image
FROM dev AS builder

COPY --link . .


# Production image, copy all the files and run nginx
FROM nginx_upstream AS prod

WORKDIR /srv/app

RUN chown -R 101:101 /srv/app

RUN rm /etc/nginx/conf.d/default.conf
COPY --link docker/nginx/templates /etc/nginx/templates
COPY --from=builder --link --chown=101:101 /srv/app/dist/spa /srv/app

EXPOSE 80

ENV NGINX_PORT=80
ENV NGINX_HOSTNAME=localhost

CMD ["nginx", "-g", "daemon off;"]
