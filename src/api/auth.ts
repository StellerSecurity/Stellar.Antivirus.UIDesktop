// src/api/auth.ts

import { http } from "./http";

// User object shape from backend
export interface ApiUser {
    id: number;
    name: string;
    email: string | null; // Can be null from API
    role: number;
    vpn_sdk?: number; // Optional fields that may not be present
    crypto_version?: string; // Optional fields that may not be present
}

// FULL response from backend (this is what you were missing)
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

// --- LOGIN ---
export function login(payload: LoginPayload) {
    return http.post<ApiEnvelope>(
        "/api/v1/logincontroller/login",
        payload,
        false
    );
}

// --- REGISTER ---
export function register(payload: RegisterPayload) {
    return http.post<ApiEnvelope>(
        "/api/v1/logincontroller/register",
        payload,
        false
    );
}
