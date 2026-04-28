import { useBlacklist } from "@/hooks/useData";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Loader2, ServerCrash, Unlock } from "lucide-react";

import { api } from "@/api/client";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";

export function BlacklistTable() {
    const queryClient = useQueryClient();
    const { data: list = [], isLoading, isError } = useBlacklist();

    const unbanMutation = useMutation({
        mutationFn: api.unbanIp,
        onSuccess: async () => {
            await queryClient.invalidateQueries({ queryKey: ["blacklist"] });
            toast.success("IP unbanned");
        }
    });

    if (isLoading)
        return (
            <div className="flex h-[50vh] items-center justify-center">
                <div className="flex items-center gap-3 text-muted-foreground">
                    <Loader2 className="h-6 w-6 animate-spin" />
                    <span className="animate-pulse text-lg">Loading Blacklist...</span>
                </div>
            </div>
        );

    if (isError)
        return (
            <div className="flex h-[50vh] items-center justify-center flex-col gap-4">
                <ServerCrash className="h-12 w-12 text-destructive" />
                <div className="text-destructive font-semibold text-lg">
                    ERROR: Cannot Load Blacklist.
                </div>
                <p className="text-muted-foreground">
                    Assure that backend is working.
                </p>
            </div>
        );

    return (
        <div className="rounded-md border border-border bg-card">
            <Table>
                <TableHeader>
                    <TableRow className="hover:bg-transparent">
                        <TableHead>IP Address</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Banned at</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {list.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={4} className="text-center h-24 text-muted-foreground">
                                No banned IPs. System is clean.
                            </TableCell>
                        </TableRow>
                    ) : list.map(entry => (
                        <TableRow key={entry.id}>
                            <TableCell className="font-mono text-xs">{entry.ip}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">{entry.reason}</TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">{entry.timestamp}</TableCell>
                            <TableCell className="text-right">
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    className="text-muted-foreground hover:text-success"
                                    onClick={() => unbanMutation.mutate(entry.ip)}
                                >
                                    <Unlock className="h-4 w-4 mr-1" />Unban
                                </Button>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
}