import {Activity, Loader2, ServerCrash, ShieldAlert, ShieldCheck} from "lucide-react";
import {useStats} from "@/hooks/useStats";
import {MetricCard} from "@/components/dashboard/MetricCard";
import {TrafficChart} from "@/components/dashboard/TrafficChart";

export default function DashboardPage() {
    const {data: stats, isLoading, isError} = useStats();

    if (isLoading) {
        return (
            <div className="flex h-[50vh] items-center justify-center">
                <div className="flex items-center gap-3 text-muted-foreground">
                    <Loader2 className="h-6 w-6 animate-spin"/>
                    <span className="animate-pulse text-lg">Connecting to Firewall...</span>
                </div>
            </div>
        );
    }

    if (isError) {
        return (
            <div className="flex h-[50vh] items-center justify-center flex-col gap-4">
                <ServerCrash className="h-12 w-12 text-destructive"/>
                <div className="text-destructive font-semibold text-lg">
                    ERROR: Cannot connect to FastApi (Port 8000).
                </div>
                <p className="text-muted-foreground">
                    Assure that backend is working
                </p>
            </div>
        );
    }

    //  fallback 0 if data aren't available
    const total = stats?.total_logs || 0;
    const accepted = stats?.accepted || 0;
    const dropped = stats?.dropped || 0;
    const banned = stats?.banned_ips || 0;

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Dashboard Live</h1>
                <p className="text-muted-foreground">
                    Stats IRL from nftables and detection module
                </p>
            </div>

            {/* Row 1: Cards of stats */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <MetricCard
                    title="Total Analyzed Packets"
                    value={total.toLocaleString()}
                    icon={<Activity className="h-5 w-5"/>}
                    trend="Active monitorizing"
                    variant="default"
                />

                <MetricCard
                    title="Accepted packets"
                    value={accepted.toLocaleString()}
                    icon={<ShieldCheck className="h-5 w-5"/>}
                    variant="success"
                />

                <MetricCard
                    title="Blocked packets"
                    value={dropped.toLocaleString()}
                    icon={<ShieldAlert className="h-5 w-5"/>}
                    variant="danger"
                />

                <MetricCard
                    title="IPs in Blacklist"
                    value={banned.toLocaleString()}
                    icon={<ServerCrash className="h-5 w-5"/>}
                    trend="Automate/Manual Blocked"
                    variant="warning"
                />
            </div>

            {/* Row 2: Graphs */}
            <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                <TrafficChart/>

                <div
                    className="rounded-xl border border-border bg-card text-card-foreground shadow-sm flex items-center justify-center p-6 min-h-75">
                    <p className="text-muted-foreground">Flood Chart Placeholder</p>
                </div>
            </div>
        </div>
    );
}