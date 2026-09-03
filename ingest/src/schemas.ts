import { z } from 'zod';

// .strict() on the envelope: unexpected top-level fields are rejected.
// payload stays z.record(z.string(), z.unknown()) — deliberately permissive.
// The brief lists four known event types, but an unrecognized type must
// still be accepted and stored raw rather than rejected: a security
// monitor that discards events it doesn't recognize is worse than
// useless, because the novel event is exactly the one worth keeping.
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
