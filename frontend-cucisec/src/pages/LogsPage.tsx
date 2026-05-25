import { LogsTable } from "@/components/logss/LogsTable";

export default function LogsPage() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">System Logs and Activities</h1>
            </div>

            <LogsTable />
        </div>
    );
}