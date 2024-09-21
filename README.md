# auth-microservice

## Dev

1. Clone the repository
2. Run `npm install`
3. Create a `.env` file in the root of the project based on the `.env.example` file
<!-- 4. Execute prisma migrations with `npx prisma migrate dev`
4. Execute prisma seed with `npx prisma db seed` -->
5. Getting up Nats server
6. Execute app with `npm run start:dev`

## Nats

```bash
docker run -d --name nats-main -p 4222:4222 -p 6222:6222 -p 8222:8222 nats
```
