import { exec } from "child_process";
import { z } from "zod";

export const adminRouter = router({
  backup: adminProcedure.input(z.object({ dir: z.string(), keep: z.string() })).mutation(async ({ input, ctx }) => {
    exec(`tar czf /backups/${input.dir}.tgz /data`);   // BAD shell: the client's input (z.string() checks the type)
    exec(`prune --keep ${parseInt(input.keep)}`);      // ok sanitized
    exec(`notify ${ctx.user.email}`);                  // ok: ctx is the server's
  }),
});
