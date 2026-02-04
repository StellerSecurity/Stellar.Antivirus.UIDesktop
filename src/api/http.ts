// src/api/http.ts

// Force the correct API URL - don't use env var if it's wrong
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
    // Ensure base URL doesn't end with slash and path doesn't start with slash (or handle both)
    const baseUrl = USER_API_BASE_URL.replace(/\/+$/, ""); // Remove trailing slashes
    const cleanPath = path.startsWith("/") ? path : `/${path}`; // Ensure path starts with /
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

    // Check if we're in Tauri
    const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
    console.log(`[API] Base URL: ${USER_API_BASE_URL}`);
    console.log(`[API] Environment: ${isTauri ? "Tauri" : "Browser"}`, {
        method: options.method || "GET",
        url: url,
        baseUrl: USER_API_BASE_URL,
        path: path,
        hasAuth: !!options.auth,
        hasBody: !!options.body,
        body: options.body ? (typeof options.body === 'string' ? options.body.substring(0, 200) : JSON.stringify(options.body).substring(0, 200)) : undefined,
        headers: headers,
    });

    let res: Response;
    try {
        res = await fetch(url, {
            method: options.method || "GET",
            headers,
            body: options.body,
            // Add mode and credentials for CORS if needed
            mode: "cors",
            credentials: "omit",
            ...options, // Spread other options but our explicit ones take precedence
        });
    } catch (networkError: any) {
        console.error("[API] Network error details:", {
            message: networkError?.message,
            name: networkError?.name,
            stack: networkError?.stack,
            url: url,
        });
        
        // Provide more specific error messages
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
    let responseText: string = "";
    
    try {
        responseText = await res.text();
        if (responseText) {
            try {
                json = JSON.parse(responseText);
            } catch (parseError) {
                // If JSON parsing fails, json stays null
                console.warn("[API] Response is not valid JSON:", responseText.substring(0, 100));
            }
        }
    } catch (textError) {
        console.error("[API] Failed to read response text:", textError);
        // If we can't read the response at all, create error from status
        if (!res.ok) {
            const error = new Error(`Request failed with status ${res.status}: Unable to read response`);
            (error as any).status = res.status;
            (error as any).response = null;
            throw error;
        }
    }

    console.log(`[API] Response status: ${res.status}`, json || responseText.substring(0, 200));

    if (!res.ok || (json && json.response_code && json.response_code !== 200)) {
        const msg =
            json?.response_message ||
            json?.message ||
            responseText ||
            `Request failed with status ${res.status}`;
        const error = new Error(msg);
        (error as any).status = res.status;
        (error as any).response = json || { raw: responseText };
        console.error("[API] Request failed:", msg, json || responseText);
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
