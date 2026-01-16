// src/api/dashboard.ts

import { http } from "./http";

export type DashboardUser = {
    username: string;
};

export type DashboardSubscription = {
    expires_at: string | null;
    active: boolean;
};

export type DashboardResponse = {
    user: DashboardUser;
    subscription: DashboardSubscription;
};

/**
 * Fetch dashboard information (user + subscription) from the UI API.
 * Expects a personal token in the request body.
 */
export function fetchDashboard(token: string) {
    return http.post<DashboardResponse>(
        "/api/v1/dashboardcontroller/home",
        { token },
        false // token is passed in request body, not via Authorization header
    );
}
