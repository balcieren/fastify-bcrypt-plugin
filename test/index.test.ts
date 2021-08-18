import { test } from "tap";
import Fastify from "fastify";
import fastifyBcrypt from "../index";

const pwdHash = "$2b$10$8Es/etqSEcWH4SQsxQzKdO8eobWvi70PXGyr48v.Ia21MBcOA76i2";

const buildApp = async (t: Tap.Test) => {
  const fastify = Fastify({
    logger: {
      level: "error",
    },
  });

  t.teardown(() => {
    fastify.close();
  });

  return fastify;
};

test("fastify-bcrypt-plugin", async (t) => {
  t.test("without options", async (t) => {
    t.plan(1);
    const fastify = await buildApp(t);
    try {
      await fastify.register(fastifyBcrypt);
      t.ok("bcrypt" in fastify, "should not throw any error");
    } catch (err) {
      console.log(err);
      t.error(err, "should not throw any error");
    }
  });

  t.test('with "saltWorkFactor" option', async (t) => {
    t.plan(1);
    const fastify = await buildApp(t);
    try {
      await fastify.register(fastifyBcrypt, {
        saltOrRounds: 8,
      });
      t.ok("bcrypt" in fastify, "should not throw any error");
    } catch (err) {
      console.log(err);
      t.error(err, "should not throw any error");
    }
  });

  t.test("hash", async (t) => {
    t.plan(2);
    const fastify = await buildApp(t);
    try {
      await fastify.register(fastifyBcrypt);
      const hash = await fastify.bcrypt.hash("password");
      t.equal(typeof hash, "string", "should generate a hash");
      t.not(hash, "password", "should generate a hash");
    } catch (err) {
      console.log(err);
      t.error(err, "should not throw any error");
    }
  });

  t.test("compare two not matching claims", async (t) => {
    t.plan(1);
    const fastify = await buildApp(t);
    try {
      await fastify.register(fastifyBcrypt);
      const match = await fastify.bcrypt.compare("password123", pwdHash);
      t.equal(match, false, "should return false");
    } catch (err) {
      console.log(err);
      t.error(err, "should not throw any error");
    }
  });

  t.test("compare two matching claims", async (t) => {
    t.plan(1);
    const fastify = await buildApp(t);
    try {
      await fastify.register(fastifyBcrypt);

      const match = await fastify.bcrypt.compare("password", pwdHash);

      t.equal(match, true, "should return true");
    } catch (err) {
      console.log(err);
      t.error(err, "should not throw any error");
    }
  });
});
