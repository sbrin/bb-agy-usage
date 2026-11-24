import { defineRpcContract } from "@get-bb/plugin-sdk";
import { z } from "zod";

export const hostUsagePlan = z.object({
  id: z.string().min(1),
  multiplier: z.number().int().positive().nullable(),
});

export const hostUsageWindow = z.object({
  kind: z.enum(["five-hour", "weekly"]),
  label: z.string(),
  usedPercent: z.number(),
  resetsAt: z.string().nullable(),
  cost: z.object({ usedUsdCents: z.number(), limitUsdCents: z.number() }).optional(),
});

export const hostUsageState = z.discriminatedUnion("status", [
  z.object({
    status: z.literal("ok"),
    plan: hostUsagePlan.nullable().optional(),
    accountEmail: z.string().nullable(),
    planLabel: z.string().nullable(),
    windows: z.array(hostUsageWindow),
  }),
  z.object({ status: z.literal("not_installed") }),
  z.object({ status: z.literal("unauthenticated") }),
  z.object({ status: z.literal("expired") }),
  z.object({
    status: z.literal("error"),
    message: z.string(),
    accountEmail: z.string().nullable(),
    planLabel: z.string().nullable(),
  }),
]);

export const usageHostContract = defineRpcContract({
  "usage.readAgy": {
    input: z.object({}),
    output: hostUsageState,
  },
});
