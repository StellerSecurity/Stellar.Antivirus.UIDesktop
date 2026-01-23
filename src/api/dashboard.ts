// src/api/dashboard.ts

import { http } from "./http";

export type DashboardUser = {
    email: string;
};

export type DashboardSubscription = {
    expires_at: string;
    remaining_days?: number;
    status: number; // 0 = INACTIVE, 1 = ACTIVE, 2 = TRIAL
};

export type DashboardResponse = {
    user: DashboardUser;
    subscription: DashboardSubscription;
};

/**
 * Fetch dashboard information (user + subscription) from the UI API.
 * Sends token as Bearer token in Authorization header.
 */
export function fetchDashboard(token: string) {
    // Pass token via http.post's auth parameter, which will add it as Bearer token
    // We need to temporarily set the token in localStorage so http.ts can read it
    if (typeof window !== "undefined") {
        window.localStorage.setItem("stellar_auth_token", token);
    }
    
    return http.post<DashboardResponse>(
        "/api/v1/dashboardcontroller/home",
        {}, // Empty body as per API requirements
        true // Use auth: true to send Bearer token
    );
}
