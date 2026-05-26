import {Activity, Network, ServerCrash, ShieldAlert, ShieldCheck} from "lucide-react";
import {useStats} from "@/hooks/useStats";
import {MetricCard} from "@/components/dashboard/MetricCard";
import {TrafficChart} from "@/components/dashboard/TrafficChart";
import {DashboardSkeleton} from "@/components/skeletons/DashboardSkeleton.tsx";
import {FloodChart} from "@/components/dashboard/FloodChart.tsx";
import {ThreatDetections} from "@/components/dashboard/ThreatDetections.tsx";

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
                    ERROR: Cannot connect to FastAPI.
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
    const intercepted = stats?.total_intercepted || 0;

    return (
        <div className="flex flex-col h-full space-y-6 pb-2">
            <div className="shrink-0">
                <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
                <p className="text-muted-foreground">
                    Real-Time Statistics
                </p>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5 shrink-0">
                <MetricCard
                    title="Total Intercepted Packets"
                    value={intercepted.toLocaleString("de-DE")}
                    icon={<Network className="h-5 w-5"/>}
                    trend="Kernel + Userspace"
                    variant="default"
                />

                <MetricCard
                    title="Total Analyzed Packets"
                    value={total.toLocaleString("de-DE")}
                    icon={<Activity className="h-5 w-5"/>}
                    trend="Active monitoring"
                    variant="info"
                />

                <MetricCard
                    title="Accepted Packets"
                    value={accepted.toLocaleString("de-DE")}
                    icon={<ShieldCheck className="h-5 w-5"/>}
                    variant="success"
                />

                <MetricCard
                    title="Dropped Packets"
                    value={dropped.toLocaleString("de-DE")}
                    icon={<ShieldAlert className="h-5 w-5"/>}
                    variant="danger"
                />

                <MetricCard
                    title="Blacklist"
                    value={banned.toLocaleString("de-DE")}
                    icon={<ServerCrash className="h-5 w-5"/>}
                    trend="Auto/Manual Banned IPs"
                    variant="warning"
                />
            </div>

            <div className="flex flex-col gap-4 flex-1 min-h-0">
                <div className="flex-1 min-h-0">
                    <TrafficChart/>
                </div>

                <div className="grid gap-4 grid-cols-1 lg:grid-cols-2 shrink-0">
                    <FloodChart/>
                    <ThreatDetections/>
                </div>
            </div>
        </div>
    );
}