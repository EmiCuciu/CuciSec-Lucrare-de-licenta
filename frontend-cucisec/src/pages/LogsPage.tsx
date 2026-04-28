import { LogsTable } from "@/components/logss/LogsTable";

export default function LogsPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">System Logs</h1>
                <p className="text-muted-foreground">Packet and action history </p>
            </div>

            <LogsTable />
        </div>
    );
}