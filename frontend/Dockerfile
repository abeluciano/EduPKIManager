FROM node:22-alpine AS build

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json frontend/tsconfig.json frontend/index.html frontend/vite.config.ts /app/frontend/
COPY frontend/src /app/frontend/src
COPY frontend/public /app/frontend/public
RUN npm ci && npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/frontend/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80 443
