// src/api/auth.ts

import { http } from "./http";

// User object shape from backend
export interface ApiUser {
    id: number;
    name: string;
    email: string | null; // Can be null from API
    role: number;
    token?: string; // Backend returns the auth token here
    vpn_sdk?: number; // Optional fields that may not be present
    crypto_version?: string; // Optional fields that may not be present
}

// FULL response from backend
export interface ApiEnvelope {
    response_code: number;
    response_message: string;
    user: ApiUser;
    token: string;
    subscription_id?: string;
}

export interface LoginPayload {
    username: string;
    password: string;
}

export interface RegisterPayload {
    username: string;
    password: string;
}

function normalizeAuthResponse(res: ApiEnvelope): ApiEnvelope {
    return {
        ...res,
        token: res.token || res.user?.token || "",
    };
}

// --- LOGIN ---
export async function login(payload: LoginPayload) {
    const res = await http.post<ApiEnvelope>(
        "/api/v1/logincontroller/login",
        payload,
        false
    );

    return normalizeAuthResponse(res);
}

// --- REGISTER ---
export async function register(payload: RegisterPayload) {
    const res = await http.post<ApiEnvelope>(
        "/api/v1/logincontroller/register",
        payload,
        false
    );

    return normalizeAuthResponse(res);
}