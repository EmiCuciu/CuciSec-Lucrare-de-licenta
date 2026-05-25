import {useQuery} from "@tanstack/react-query";
import {api} from "@/api/client.ts";

export const useRules = () => {
    return useQuery({
        queryKey: ["rules"],
        queryFn: api.getRules,
        refetchInterval: 2000,
        refetchIntervalInBackground: false,
        staleTime: 1000,
        refetchOnWindowFocus: false
    });
};

export const useLogs = (limit = 50) => {
    return useQuery({
        queryKey: ["logs", limit],
        queryFn: () => api.getLogs(limit),
        refetchInterval: 1500,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: false,
        staleTime: 1250
    });
};

export const useBlacklist = () => {
    return useQuery({
        queryKey: ["blacklist"],
        queryFn: api.getBlacklist,
        refetchInterval: 1500,
        refetchIntervalInBackground: false,
        staleTime: 1250,
        refetchOnWindowFocus: false
    });
};