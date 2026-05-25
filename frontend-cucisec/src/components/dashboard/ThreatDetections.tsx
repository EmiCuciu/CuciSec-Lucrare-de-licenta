import {useStats} from "@/hooks/useStats";
import {Card, CardContent, CardHeader, CardTitle} from "@/components/ui/card";
import {Bug, Crosshair, ShieldX} from "lucide-react";

function StatBadge({ icon, label, value, color }: {
    icon: React.ReactNode;
    label: string;
    value: number;
    color: string;
}) {
    return (
        <div className="flex items-center gap-3 rounded-lg border p-3 flex-1">
            <div className="shrink-0 rounded-md p-2" style={{ backgroundColor: `${color}18` }}>
                <div style={{ color }}>{icon}</div>
            </div>
            <div className="min-w-0">
                <p className="text-xs text-muted-foreground truncate">{label}</p>
                <p className="text-xl font-bold tabular-nums">{value.toLocaleString()}</p>
            </div>
        </div>
    );
}

export function ThreatDetections() {
    const {data: stats} = useStats();

    const honeyportHits = stats?.cumulative_flood_counters?.honeyport_hits ?? 0;
    const dpiDrops = stats?.dpi_drops ?? 0;
    const recentBans = stats?.recent_bans ?? [];

    return (
        <Card className="flex flex-col h-full overflow-hidden">
            <CardHeader className="shrink-0 pb-2">
                <CardTitle>Threat Detections</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-4 flex-1 min-h-0 p-6 pt-0">
                <div className="flex gap-3">
                    <StatBadge
                        icon={<Crosshair className="h-4 w-4"/>}
                        label="Honeyport Hits"
                        value={honeyportHits}
                        color="#06b6d4"
                    />
                    <StatBadge
                        icon={<Bug className="h-4 w-4"/>}
                        label="DPI Drops"
                        value={dpiDrops}
                        color="#f97316"
                    />
                </div>

                <div className="flex flex-col flex-1 min-h-0">
                    <div className="flex items-center gap-2 mb-2">
                        <ShieldX className="h-4 w-4 text-destructive"/>
                        <span className="text-sm font-medium">Recent Bans</span>
                    </div>

                    {recentBans.length === 0 ? (
                        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
                            No bans recorded yet.
                        </div>
                    ) : (
                        <div className="flex flex-col gap-1 overflow-auto flex-1 min-h-0">
                            {recentBans.map((ban, i) => (
                                <div
                                    key={i}
                                    className="flex items-start justify-between gap-2 rounded-md px-2 py-1.5 text-xs hover:bg-accent transition-colors"
                                >
                                    <span className="font-mono font-semibold text-destructive shrink-0">
                                        {ban.ip}
                                    </span>
                                    <span className="text-muted-foreground truncate flex-1 text-right">
                                        {ban.reason}
                                    </span>
                                    <span className="text-muted-foreground shrink-0 tabular-nums">
                                        {ban.timestamp.slice(11, 16)}
                                    </span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </CardContent>
        </Card>
    );
}