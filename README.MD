# fastify-bcrypt-plugin

[![Version](https://img.shields.io/npm/v/fastify-bcrypt-plugin.svg)](https://www.npmjs.com/package/fastify-bcrypt-plugin)

A Bcrypt hash generator & checker for Fastify

## Installation

```bash
yarn add fastify-bcrypt-plugin
or
npm install fastify-bcrypt-plugin
```

## Usage

Register plugin

```js
import fastifyBcrypt from "fastify-bcrypt-plugin";

fastify.register(fastifyBcrypt);
```

If you use with TypeScript , you have to give this type to avoid error

```js
import Fastify, { FastifyInstance } from "fastify";

const fastify: FastifyInstance = Fastify();
```

If you want to change the salt work factor

```js
fastify.register(fastifyBcrypt, { saltOrRounds: 15 }); // The salt work factor for the bcrypt algorithm. The default value is 10.
```

Use with fastify decorate

```js
fastify.get("/", async (request, reply) => {
  const hashedPassword = await fastify.bcrypt.hash(request.body.password);
  const isPasswordCompared = await fastify.bcrypt.compare(
    request.body.password,
    hashedPassword
  );
  return { hashedPassword, isPasswordCompared };
});
```

Use with request decorate

```js
fastify.get("/", async (request, reply) => {
  const hashedPassword = await request.bcrypt.hash(request.body.password);
  const isPasswordCompared = await request.bcrypt.compare(
    request.body.password,
    hashedPassword
  );
  return { hashedPassword, isPasswordCompared };
});
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
