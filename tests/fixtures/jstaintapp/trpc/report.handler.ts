import { prisma } from "@calcom/prisma";

type Options = { ctx: { user: { id: number } }; input: { sortBy: string; limit: number } };

// cal.com: a procedure's handler in its own file
export const reportHandler = async ({ ctx, input }: Options) => {
  const { sortBy } = input;
  await prisma.$queryRawUnsafe(`SELECT * FROM "Booking" ORDER BY ${sortBy}`);   // BAD sql
  await prisma.$queryRawUnsafe(`SELECT * FROM "Booking" WHERE "userId" = ${ctx.user.id}`);   // ok: the session's
};
