import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Ban, ChevronLeft, ChevronRight, Loader2, ServerCrash } from "lucide-react";

import { api } from "@/api/client";
import { useLogs } from "@/hooks/useData";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const PAGE_SIZE = 20;

const ICMP_TYPES: Record<number, string> = {
    // ICMPv4
    0: "Echo Reply",
    3: "Dest Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
    // ICMPv6
    128: "Echo Request",
    129: "Echo Reply",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
};

function icmpTypeName(type: number): string {
    return ICMP_TYPES[type] ?? `Type ${type}`;
}

function endpoint(ip: string, port: number, protocol: string): string {
    if (protocol === "ICMP" || protocol === "ICMPv6") return ip;
    return port ? `${ip}:${port}` : ip;
}

export function LogsTable() {
    const [filterProtocol, setFilterProtocol] = useState("all");
    const [filterAction, setFilterAction] = useState("all");
    const [filterIp, setFilterIp] = useState("");
    const [page, setPage] = useState(0);

    const queryClient = useQueryClient();
    const { data: logs = [], isLoading, isError } = useLogs(500);

    const banMutation = useMutation({
        mutationFn: ({ ip }: { ip: string }) => api.banIp(ip, "Manual Ban from Logs"),
        onSuccess: async (_, { ip }) => {
            await queryClient.invalidateQueries({ queryKey: ["blacklist"] });
            toast.success(`${ip} banned successfully`);
        },
        onError: (error: Error) => {
            toast.error(`Failed to ban IP: ${error.message}`);
        }
    });

    const filtered = logs.filter(log => {
        if (filterProtocol !== "all" && log.protocol !== filterProtocol) return false;
        if (filterAction === "ACCEPT" && !log.action_taken.includes("ACCEPT")) return false;
        if (filterAction === "DROP" && !log.action_taken.includes("DROP")) return false;
        return !(filterIp && !log.ip_src.includes(filterIp) && !log.ip_dst.includes(filterIp));
    });

    const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

    if (isLoading)
        return (
            <div className="flex h-[50vh] items-center justify-center">
                <div className="flex items-center gap-3 text-muted-foreground">
                    <Loader2 className="h-6 w-6 animate-spin" />
                    <span className="animate-pulse text-lg">Loading Logs...</span>
                </div>
            </div>
        );

    if (isError)
        return (
            <div className="flex h-[50vh] items-center justify-center flex-col gap-4">
                <ServerCrash className="h-12 w-12 text-destructive" />
                <div className="text-destructive font-semibold text-lg">
                    ERROR: Cannot Load LogsTable.
                </div>
                <p className="text-muted-foreground">
                    Assure that backend is working.
                </p>
            </div>
        );

    return (
        <div className="space-y-4">
            {/* Filters */}
            <div className="flex gap-3 flex-wrap">
                <Select value={filterProtocol} onValueChange={v => { setFilterProtocol(v); setPage(0); }}>
                    <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All protocols</SelectItem>
                        <SelectItem value="TCP">TCP</SelectItem>
                        <SelectItem value="UDP">UDP</SelectItem>
                        <SelectItem value="ICMP">ICMP</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={filterAction} onValueChange={v => { setFilterAction(v); setPage(0); }}>
                    <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All actions</SelectItem>
                        <SelectItem value="ACCEPT">ACCEPT</SelectItem>
                        <SelectItem value="DROP">DROP</SelectItem>
                    </SelectContent>
                </Select>
                <Input
                    placeholder="Filter by IP..."
                    value={filterIp}
                    onChange={e => { setFilterIp(e.target.value); setPage(0); }}
                    className="w-44"
                />
                <span className="text-sm text-muted-foreground self-center">{filtered.length} results</span>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border bg-card">
                <Table>
                    <TableHeader>
                        <TableRow className="hover:bg-transparent">
                            <TableHead>Time</TableHead>
                            <TableHead>Protocol</TableHead>
                            <TableHead>Source</TableHead>
                            <TableHead>Destination</TableHead>
                            <TableHead>Action</TableHead>
                            <TableHead>Details</TableHead>
                            <TableHead className="text-right">Ban</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {paged.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={7} className="text-center h-24 text-muted-foreground">
                                    No logs matching the criteria.
                                </TableCell>
                            </TableRow>
                        ) : paged.map(log => {
                            const isDrop = log.action_taken.startsWith("DROP");
                            const isIcmp = log.protocol === "ICMP" || log.protocol === "ICMPv6";
                            return (
                                <TableRow key={log.id} className={isDrop ? "bg-destructive/5" : "bg-success/5"}>
                                    <TableCell
                                        className="font-mono text-sm text-muted-foreground whitespace-nowrap"
                                        title={log.timestamp}
                                    >
                                        {new Date(log.timestamp).toLocaleTimeString()}
                                    </TableCell>
                                    <TableCell>
                                        <Badge variant="outline" className="font-mono text-xs">
                                            {log.protocol}
                                        </Badge>
                                    </TableCell>
                                    <TableCell className="font-mono text-sm">
                                        {endpoint(log.ip_src, log.port_src, log.protocol)}
                                    </TableCell>
                                    <TableCell className="font-mono text-sm">
                                        {isIcmp ? (
                                            <span>
                                                {log.ip_dst}{" "}
                                                <span className="text-xs text-muted-foreground">
                                                    ({icmpTypeName(log.port_dst)})
                                                </span>
                                            </span>
                                        ) : (
                                            endpoint(log.ip_dst, log.port_dst, log.protocol)
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        <Badge
                                            variant={isDrop ? "destructive" : "default"}
                                            className={!isDrop ? "bg-success hover:bg-success/80" : ""}
                                        >
                                            {isDrop ? "DROP" : "ACCEPT"}
                                        </Badge>
                                    </TableCell>
                                    <TableCell
                                        className="text-sm text-muted-foreground max-w-56 truncate"
                                        title={log.details}
                                    >
                                        {log.details || "—"}
                                    </TableCell>
                                    <TableCell className="text-right">
                                        <Button
                                            variant="ghost" size="icon"
                                            className="text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                                            onClick={() => banMutation.mutate({ ip: log.ip_src })}
                                        >
                                            <Ban className="h-4 w-4" />
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            );
                        })}
                    </TableBody>
                </Table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-end gap-2">
                <Button variant="ghost" size="icon" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                    <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-sm text-muted-foreground">{page + 1} / {totalPages}</span>
                <Button variant="ghost" size="icon" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
                    <ChevronRight className="h-4 w-4" />
                </Button>
            </div>
        </div>
    );
}