// src/api/http.ts

export const USER_API_BASE_URL =
    import.meta.env.VITE_USER_API_BASE_URL ||
    "https://stellarsecurityuidesktopapiprod.azurewebsites.net";

function getToken(): string | null {
    if (typeof window === "undefined") return null;
    try {
        return window.localStorage.getItem("stellar_auth_token");
    } catch {
        return null;
    }
}

async function request<T>(
    path: string,
    options: RequestInit & { auth?: boolean } = {}
): Promise<T> {
    const url = `${USER_API_BASE_URL}${path}`;

    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(options.headers as Record<string, string> | undefined),
    };

    if (options.auth) {
        const token = getToken();
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
    }

    const res = await fetch(url, {
        ...options,
        headers,
    });

    let json: any = null;
    try {
        json = await res.json();
    } catch {

    }

    if (!res.ok || (json && json.response_code && json.response_code !== 200)) {
        const msg =
            json?.response_message ||
            json?.message ||
            `Request failed with status ${res.status}`;
        const error = new Error(msg);
        (error as any).status = res.status;
        (error as any).response = json;
        throw error;
    }

    return json as T;
}

export const http = {
    get: <T>(path: string, auth = false) =>
        request<T>(path, { method: "GET", auth }),
    post: <T>(path: string, body: unknown, auth = false) =>
        request<T>(path, {
            method: "POST",
            body: JSON.stringify(body),
            auth,
        }),
};
