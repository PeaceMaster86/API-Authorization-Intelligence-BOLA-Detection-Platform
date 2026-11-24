import type { Endpoint, ObjectRecord, Report } from "./types";

const reportUrl = import.meta.env.VITE_REPORT_URL ?? "/report.json";
const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "/api";

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const loadReport = (): Promise<Report> => getJson<Report>(reportUrl);
export const loadEndpoints = (): Promise<Endpoint[]> =>
  getJson<Endpoint[]>(`${apiBaseUrl}/endpoints`);
export const loadObjects = (): Promise<ObjectRecord[]> =>
  getJson<ObjectRecord[]>(`${apiBaseUrl}/objects`);
