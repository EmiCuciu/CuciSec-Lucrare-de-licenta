import {Activity, ServerCrash, ShieldAlert, ShieldCheck} from "lucide-react";
import {useStats} from "@/hooks/useStats";
import {MetricCard} from "@/components/dashboard/MetricCard";
import {TrafficChart} from "@/components/dashboard/TrafficChart";
import {DashboardSkeleton} from "@/components/skeletons/DashboardSkeleton.tsx";

export default function DashboardPage() {
    const {data: stats, isLoading, isError} = useStats();

    if (isLoading) {
        return <DashboardSkeleton/>;
    }

    if (isError) {
        return (
            <div className="flex h-full items-center justify-center flex-col gap-4">
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

    const total = stats?.total_logs || 0;
    const accepted = stats?.accepted || 0;
    const dropped = stats?.dropped || 0;
    const banned = stats?.banned_ips || 0;

    return (
        <div className="flex flex-col h-full space-y-6 pb-2">
            <div className="shrink-0">
                <h1 className="text-3xl font-bold tracking-tight">Dashboard Live</h1>
                <p className="text-muted-foreground">
                    Stats IRL from nftables and detection module
                </p>
            </div>

            {/* Row 1: Cards of stats */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 shrink-0">
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
                    title="Dropped packets"
                    value={dropped.toLocaleString()}
                    icon={<ShieldAlert className="h-5 w-5"/>}
                    variant="danger"
                />

                <MetricCard
                    title="IPs in Blacklist"
                    value={banned.toLocaleString()}
                    icon={<ServerCrash className="h-5 w-5"/>}
                    trend="Auto/Manual Block"
                    variant="warning"
                />
            </div>

            <div className="grid gap-4 grid-cols-1 lg:grid-cols-2 flex-1 min-h-0">
                <TrafficChart/>

                {/* TODO - to implement this shit */}
                <div
                    className="rounded-xl border border-border bg-card text-card-foreground shadow-sm flex items-center justify-center h-full">
                    <p className="text-muted-foreground">Flood Chart Placeholder</p>
                </div>
            </div>
        </div>
    );
}