// src/api/auth.ts

import { http } from "./http";

export interface ApiUser {
    id: number;
    name: string;
    email: string | null;
    role?: number;
    token?: string;
    vpn_sdk?: number;
    crypto_version?: string;
}

export interface ApiEnvelope {
    response_code: number;
    response_message: string;
    user?: ApiUser;
    token?: string;
    subscription_id?: string | number;
}

export interface LoginPayload {
    username: string;
    password: string;
}

export interface RegisterPayload {
    username: string;
    password: string;
}

export function login(payload: LoginPayload) {
    return http.post<ApiEnvelope>(
        "/api/v1/logincontroller/login",
        payload,
        false
    );
}

export function register(payload: RegisterPayload) {
    return http.post<ApiEnvelope>(
        "/api/v1/logincontroller/register",
        payload,
        false
    );
}