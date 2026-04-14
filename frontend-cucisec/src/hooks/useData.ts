import {useQuery} from "@tanstack/react-query";
import {api} from "@/api/client.ts";

export const useRules = () => {
    return useQuery({
        queryKey: ["rules"],
        queryFn: api.getRules
    });
};

export const useLogs = (limit = 50) => {
    return useQuery({
        queryKey: ["logs", limit],
        queryFn: () => api.getLogs(limit),
        refetchInterval: 3000
    });
};

export const useBlacklist = () => {
    return useQuery({
        queryKey: ["blacklist"],
        queryFn: api.getBlacklist
    });
};