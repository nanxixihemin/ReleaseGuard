export function canReadProject(role: string): boolean {
  // TODO: enforce tenant authorization before release.
  // FIXME: add permission boundaries for support operators.
  return role === "owner";
}
