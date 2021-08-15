import { FastifyPluginCallback } from "fastify";
import fp from "fastify-plugin";
import bcrypt from "bcrypt";

export type BcryptOptions = { saltOrRounds?: string | number };

type BcryptPlugin = {
  hash: {
    (data: string | Buffer): Promise<string>;
    (
      data: string | Buffer,
      callback: (err: Error | undefined, encrypted: string) => any
    ): void;
  };
  compare: typeof bcrypt.compare;
};

const bcryptPlugin: FastifyPluginCallback<Partial<BcryptOptions>> = (
  fastify,
  options,
  done
) => {
  if (fastify.bcrypt)
    return done(new Error("fastify-bcrypt-plugin has been defined before"));

  const hash: BcryptPlugin["hash"] = (data) =>
    bcrypt.hash(data, options.saltOrRounds || 10);

  const compare: BcryptPlugin["compare"] = (data, encrypted) =>
    bcrypt.compare(data, encrypted);

  fastify
    .decorate("bcrypt", { hash, compare })
    .decorateRequest("bcrypt", { hash, compare });

  done();
};

const fastifyBcrypt = fp(bcryptPlugin, {
  fastify: "3.x",
  name: "fastify-bcrypt,plugin",
});

export default fastifyBcrypt;

declare module "fastify" {
  interface FastifyRequest {
    bcrypt: BcryptPlugin;
  }
  interface FastifyInstance {
    bcrypt: BcryptPlugin;
  }
}
