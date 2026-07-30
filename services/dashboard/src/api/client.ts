// The dashboard talks ONLY to the Gateway's published port -- this base URL
// is what the BROWSER resolves, not a Docker-network address. Never point
// this at postgres/redis/opa/isolation-forest directly (see CLAUDE.md: the
// dashboard reaches the system solely through the Gateway).
export const BASE_URL = (import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, init);
}

export async function apiFetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(path, init);
  if (!response.ok) {
    // Deliberately not logging the response body -- it's a security console,
    // and error bodies from auth endpoints are exactly the kind of thing that
    // shouldn't end up in a browser console transcript.
    throw new ApiError(response.status, `${path} failed (${response.status})`);
  }
  return (await response.json()) as T;
}
