import api from "./client";
import type { LoginPayload, RegisterPayload } from "./schemas";

export async function login(payload: LoginPayload) {
  const { data } = await api.post<{ access: string; refresh: string }>(
    "/api/auth/login/",
    payload,
  );
  return data;
}

export async function register(payload: RegisterPayload) {
  const { data } = await api.post<{
    message: string;
    user: { id: number; username: string; email: string; role: string };
  }>("/api/auth/register/", payload);
  return data;
}

export async function refreshToken(refresh: string) {
  const { data } = await api.post<{ access: string }>("/api/auth/refresh/", {
    refresh,
  });
  return data;
}
