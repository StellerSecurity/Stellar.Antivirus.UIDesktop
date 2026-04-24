// src/api/http.ts

export const USER_API_BASE_URL = "https://stellaruidesktopantivirusapiprod.azurewebsites.net";

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
    const baseUrl = USER_API_BASE_URL.replace(/\/+$/, "");
    const cleanPath = path.startsWith("/") ? path : `/${path}`;
    const url = `${baseUrl}${cleanPath}`;

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

    if (import.meta.env.DEV) {
        console.debug("[API] Request", {
            method: options.method || "GET",
            url,
            hasAuth: !!options.auth,
            hasBody: !!options.body,
        });
    }

    let res: Response;
    try {
        res = await fetch(url, {
            method: options.method || "GET",
            headers,
            body: options.body,
            mode: "cors",
            credentials: "omit",
            ...options,
        });
    } catch (networkError: any) {
        console.error("[API] Network error details:", {
            message: networkError?.message,
            name: networkError?.name,
            url,
        });

        let errorMessage = "Network error: Failed to connect to server";
        if (networkError?.message?.includes("Failed to fetch") || networkError?.message?.includes("NetworkError")) {
            errorMessage = `Cannot connect to ${USER_API_BASE_URL}. Please check:\n- Your internet connection\n- If the API server is running\n- If the URL is correct`;
        } else if (networkError?.message?.includes("CORS")) {
            errorMessage = "CORS error: The API server may not allow requests from this origin";
        } else if (networkError?.message) {
            errorMessage = `Network error: ${networkError.message}`;
        }

        const error = new Error(errorMessage);
        (error as any).isNetworkError = true;
        (error as any).originalError = networkError;
        (error as any).url = url;
        throw error;
    }

    let json: any = null;
    let responseText = "";

    try {
        responseText = await res.text();
        if (responseText) {
            try {
                json = JSON.parse(responseText);
            } catch {
                if (import.meta.env.DEV) {
                    console.warn("[API] Response is not valid JSON", { status: res.status });
                }
            }
        }
    } catch (textError) {
        console.error("[API] Failed to read response text:", textError);
        if (!res.ok) {
            const error = new Error(`Request failed with status ${res.status}: Unable to read response`);
            (error as any).status = res.status;
            (error as any).response = null;
            throw error;
        }
    }

    if (import.meta.env.DEV) {
        console.debug("[API] Response", { status: res.status });
    }

    if (!res.ok || (json && json.response_code && json.response_code !== 200)) {
        const msg =
            json?.response_message ||
            json?.message ||
            responseText ||
            `Request failed with status ${res.status}`;
        const error = new Error(msg);
        (error as any).status = res.status;
        (error as any).response = json || { raw: responseText };
        console.error("[API] Request failed:", msg);
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
