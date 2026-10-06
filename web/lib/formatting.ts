export function formatDate(d: Date | string): string {
  return new Date(d).toISOString();
}
