// src/api/auth.ts

import { http } from "./http";

// User object shape from backend
export interface ApiUser {
    id: number;
    name: string;
    email: string;
    role: number;
    vpn_sdk: number;
    crypto_version: string;
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
