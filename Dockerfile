# 残業 — 五阶段 Web 密室
# 无第三方依赖，纯 Node 内置模块，镜像很小
FROM node:22-alpine

WORKDIR /app

COPY package.json server.js ./
COPY public ./public

ENV PORT=3000 \
    NODE_ENV=production

# 平台把动态 flag 注入到下面任意一个变量里，服务启动时按顺序取第一个非空的
# 分片：flag 会被均分成 5 段，五个阶段各露一段
ENV CTF_FLAG=""

EXPOSE 3000
CMD ["node", "server.js"]
