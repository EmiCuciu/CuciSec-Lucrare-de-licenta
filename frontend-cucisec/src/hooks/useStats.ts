import {useQuery} from "@tanstack/react-query";
import {api} from "@/api/client.ts";

export const useStats = () => {
    return useQuery({
        queryKey: ["stats"],
        queryFn: api.getStats,
        refetchInterval: 1000,
        // if user switch tabs stop pooling
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
        staleTime: 900
    });
};

export const useLogCounts = () => {
    return useQuery({
        queryKey: ["logCounts"],
        queryFn: api.getLogCounts,
        refetchInterval: 2000,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: true,
        staleTime: 1900
    })
}