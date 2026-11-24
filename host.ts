import { experimental_defineHostEntry } from "@get-bb/plugin-sdk";
import { readAgyUsage } from "./agy-usage.js";
import { hostUsageState, usageHostContract } from "./usage-host-contract.js";

export default experimental_defineHostEntry({
  contract: usageHostContract,
  handlers: {
    async "usage.readAgy"() {
      const result = await readAgyUsage({ agyCli: "agy" });
      return hostUsageState.parse(result.supported
        ? result.usage
        : { status: "error", message: "AGY usage is unsupported.", accountEmail: null, planLabel: null });
    },
  },
});
