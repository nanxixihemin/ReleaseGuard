const configuredApiUrl = import.meta.env.VITE_API_URL;

export const apiUrl = configuredApiUrl ?? "http://localhost:8080";
