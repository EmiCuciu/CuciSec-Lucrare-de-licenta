import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus } from "lucide-react";

import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { BlacklistEntry } from "@/types/api";

export function AddBanModal() {
    const [open, setOpen] = useState(false);
    const [ip, setIp] = useState("");
    const [reason, setReason] = useState("");
    const queryClient = useQueryClient();

    const banMutation = useMutation({
        mutationFn: () => api.banIp(ip, reason || "Manual Ban"),
        onSuccess: (newEntry) => {
            queryClient.setQueryData<BlacklistEntry[]>(["blacklist"], (oldData) => {
                return oldData ? [...oldData, newEntry] : [newEntry];
            });
            toast.success(`${ip} banned`);
            setOpen(false);
            setIp("");
            setReason("");
        },
        onError: (error: Error) => {
            toast.error(`Failed to ban ${ip}: ${error.message}`);
        }
    });

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant="destructive">
                    <Plus className="mr-2 h-4 w-4" /> Manual Ban
                </Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Ban IP manually</DialogTitle>
                </DialogHeader>
                <div className="space-y-3">
                    <Input placeholder="IP address" value={ip} onChange={e => setIp(e.target.value)} />
                    <Input placeholder="Reason (optional)" value={reason} onChange={e => setReason(e.target.value)} />
                    <Button
                        className="w-full"
                        variant="destructive"
                        disabled={!ip || banMutation.isPending}
                        onClick={() => banMutation.mutate()}
                    >
                        {banMutation.isPending ? "Banning..." : "Ban IP"}
                    </Button>
                </div>
            </DialogContent>
        </Dialog>
    );
}