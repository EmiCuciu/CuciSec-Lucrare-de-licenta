import {BlacklistEntry, LogCount, LogEntry, Rule, Stats} from "@/types/api.ts";

const API_BASE = "/api";

// wrapper function for fetch
async function fetcher<T>(url: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${url}`, options);
    if (!response.ok) {
        throw new Error(`[ERROR API]: ${response.status} ${response.statusText}`);
    }
    return response.json();
}

export const api = {

    /// Rules
    getRules: () => fetcher<Rule[]>('/rules'),
    addRule: (rule: Omit<Rule, "id">) => fetcher<Rule>('/rules', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(rule)
    }),
    deleteRule: (id: number) => fetcher<{ message: string }>(`/rules/${id}`, {
        method: 'DELETE'
    }),
    toggleRule: (id: number, enabled: number) => fetcher<Rule>(`/rules/${id}/toggle`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled})
    }),


    /// Logs
    getLogs: (limit = 50) => fetcher<LogEntry[]>(`/logs?limit=${limit}`),
    getLogCounts: () => fetcher<LogCount[]>('/logs/count'),


    /// Blacklist
    getBlacklist: () => fetcher<BlacklistEntry[]>('/blacklist'),
    banIp: (ip: string, reason: string) => fetcher<BlacklistEntry>('/blacklist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip, reason})
    }),
    unbanIp: (ip: string) => fetcher<{ message: string }>(`/blacklist/${ip}`, {
        method: 'DELETE'
    }),


    /// Stats
    getStats: () => fetcher<Stats>('/stats'),

};