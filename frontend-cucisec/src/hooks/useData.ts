import {useQuery} from "@tanstack/react-query";
import {api} from "@/api/client.ts";

export const useRules = () => {
    return useQuery({
        queryKey: ["rules"],
        queryFn: api.getRules,
        staleTime: 5000,
        refetchOnWindowFocus: false
    });
};

export const useLogs = (limit = 50) => {
    return useQuery({
        queryKey: ["logs", limit],
        queryFn: () => api.getLogs(limit),
        refetchInterval: 3000,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: false,
        staleTime: 2500
    });
};

export const useBlacklist = () => {
    return useQuery({
        queryKey: ["blacklist"],
        queryFn: api.getBlacklist,
        staleTime: 3000,
        refetchOnWindowFocus: false
    });
};