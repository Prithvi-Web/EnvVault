/** Compact relative time for the secrets table ("just now", "3h ago", "Mar 3"). */
export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Last path component, for compact project subtitles. */
export function pathTail(path: string): string {
  const parts = path.split(/[/\\]/).filter(Boolean);
  return parts.length > 1 ? `…/${parts[parts.length - 1]}` : path;
}
