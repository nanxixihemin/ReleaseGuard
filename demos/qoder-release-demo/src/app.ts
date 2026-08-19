import { DEBUG, productionApiUrl } from "./config";
import { mayServeReleaseTraffic } from "./auth";

export function releaseSummary(): string {
  const state = DEBUG ? "diagnostic" : "release";
  const traffic = mayServeReleaseTraffic() ? "enabled" : "disabled";
  return `${state}:${traffic}:${productionApiUrl}`;
}
