FROM node:22-slim AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY web ./web
RUN corepack enable && pnpm install --frozen-lockfile && pnpm --filter @traceatlas/web build
FROM node:22-slim
WORKDIR /app
COPY --from=build /app/web/.next ./web/.next
CMD ["pnpm", "--filter", "@traceatlas/web", "start"]
