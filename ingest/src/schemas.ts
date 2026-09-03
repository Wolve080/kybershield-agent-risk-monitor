import { z } from "zod";

export const eventSchema = z
  .object({
    event_id: z.string().min(1),
    agent_id: z.string().min(1),
    timestamp: z.iso.datetime(),
    type: z.string().min(1),
    payload: z.record(z.string(), z.unknown()),
    tags: z.array(z.string()).optional(),
  })
  .strict();

export type EventInput = z.infer<typeof eventSchema>;
