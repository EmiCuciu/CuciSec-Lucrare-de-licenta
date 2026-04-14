import {useMutation, useQueryClient} from "@tanstack/react-query";
import {Loader2, ServerCrash, Trash2} from "lucide-react";
import {toast} from "sonner";

import {useRules} from "@/hooks/useData.ts";
import {api} from "@/api/client.ts";
import {Table, TableBody, TableCell, TableHead, TableHeader, TableRow,} from "@/components/ui/table";
import {Badge} from "@/components/ui/badge";
import {Switch} from "@/components/ui/switch";
import {Button} from "@/components/ui/button";


export function RulesTable() {
    const {data: rules = [], isLoading, isError} = useRules();
    const queryClient = useQueryClient();

    const toggleMutation = useMutation({
        mutationFn: ({id, enabled}: { id: number, enabled: number }) => api.toggleRule(id, enabled),
        onSuccess: async () => {
            await queryClient.invalidateQueries({queryKey: ["rules"]});
            toast.info("Rule status updated");
        },
        onError: (error: Error) => {
            toast.error(`Error at toggle: ${error.message}`);
        }
    });

    const deleteMutation = useMutation({
        mutationFn: api.deleteRule,
        onSuccess: async () => {
            await queryClient.invalidateQueries({queryKey: ["rules"]});
            toast.success("Rule deleted");
        },
        onError: (error: Error) => {
            toast.error(`Error at deleting: ${error.message}`);
        }
    });


    if (isLoading)
        return (
            <div className="flex h-[50vh] items-center justify-center">
                <div className="flex items-center gap-3 text-muted-foreground">
                    <Loader2 className="h-6 w-6 animate-spin"/>
                    <span className="animate-pulse text-lg">Loading Rules...</span>
                </div>
            </div>
        );

    if (isError)
        return (
            <div className="flex h-[50vh] items-center justify-center flex-col gap-4">
                <ServerCrash className="h-12 w-12 text-destructive"/>
                <div className="text-destructive font-semibold text-lg">
                    ERROR: Cannot Load RuleTable.
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
                        <TableHead className="w-25">Status</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead>Source IP</TableHead>
                        <TableHead>Port</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead className="text-right">Manage</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {rules.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={7} className="text-center h-24 text-muted-foreground">
                                No active rules. System is running on default policies.
                            </TableCell>
                        </TableRow>
                    ) : (
                        rules.map((rule) => (
                            <TableRow key={rule.id}>
                                <TableCell>
                                    <Switch checked={rule.enabled === 1} onCheckedChange={(checked) =>
                                        toggleMutation.mutate({id: rule.id, enabled: checked ? 1 : 0})
                                    }
                                    />
                                </TableCell>
                                <TableCell>
                                    <Badge variant={rule.action === "ACCEPT" ? "default" : "destructive"}
                                           className={rule.action === "ACCEPT" ? "bg-success hover:bg-success/80" : ""}>
                                        {rule.action}
                                    </Badge>
                                </TableCell>
                                <TableCell className="font-mono text-xs">{rule.protocol || "ANY"}</TableCell>
                                <TableCell className="font-mono text-xs">{rule.ip_src || "ANY"}</TableCell>
                                <TableCell className="font-mono text-xs">{rule.port || "ANY"}</TableCell>
                                <TableCell className="font-mono text-xs">{rule.description || "-"}</TableCell>
                                <TableCell className="text-right">
                                    <Button variant="ghost" size="icon"
                                            className="text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                                            onClick={() => deleteMutation.mutate(rule.id)}
                                    >
                                        <Trash2 className="h-4 w-4"/>
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))
                    )}
                </TableBody>
            </Table>
        </div>
    );
}