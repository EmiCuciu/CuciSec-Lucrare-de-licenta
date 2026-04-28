import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Rectangle } from "recharts";
import { useStats } from "@/hooks/useStats";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function FloodChart() {
    const { data: stats } = useStats();

    const chartData = stats ? [
        { name: "TCP SYN", value: stats.flood_counters.tcp_syn_flood_dropped || 0, color: "#ef4444" },
        { name: "ICMP", value: stats.flood_counters.icmp_flood_dropped || 0, color: "#f97316" },
        { name: "UDP", value: stats.flood_counters.udp_flood_dropped || 0, color: "#eab308" },
        { name: "Blacklist", value: stats.flood_counters.blacklist_dropped || 0, color: "#8b5cf6" },
        { name: "Honeyport", value: stats.flood_counters.honeyport_hits || 0, color: "#06b6d4" },
    ] : [];

    const hasActivity = chartData.some(d => d.value > 0);

    return (
        <Card className="flex flex-col h-full overflow-hidden">
            <CardHeader className="shrink-0 pb-2">
                <CardTitle>Kernel Drop Counters</CardTitle>
                <CardDescription>
                    nftables hardware counters
                    {!hasActivity && " — no activity detected"}
                </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 p-6 pt-0">
                <div className="h-full w-full mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                            <XAxis dataKey="name" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                                   tickLine={false} axisLine={false} />
                            <YAxis tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                                   tickLine={false} axisLine={false} />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: "hsl(var(--popover))",
                                    borderColor: "hsl(var(--border))",
                                    borderRadius: "0.5rem"
                                }}
                                formatter={(value) => [`${value} packets dropped`, ""]}
                            />

                            <Bar
                                dataKey="value"
                                shape={(props: any) => (
                                    <Rectangle
                                        {...props}
                                        fill={props.payload.color}
                                        radius={[4, 4, 0, 0]}
                                    />
                                )}
                            />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </CardContent>
        </Card>
    );
}