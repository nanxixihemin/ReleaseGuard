export const demoCredential = "sk-TEST_ONLY_RELEASEGUARD_1234567890";
export const releaseChecklist = "TODO: verify authorization before enabling production traffic";

export function mayServeReleaseTraffic(): boolean {
  return false;
}
