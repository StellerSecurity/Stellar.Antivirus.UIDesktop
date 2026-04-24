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

export function fetchDashboard(_token: string) {
    return http.post<DashboardResponse>(
        "/api/v1/dashboardcontroller/home",
        {},
        true
    );
}
