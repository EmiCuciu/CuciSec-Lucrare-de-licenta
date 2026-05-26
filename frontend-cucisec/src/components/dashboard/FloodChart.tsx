import {Bar, BarChart, Rectangle, ResponsiveContainer, Tooltip, XAxis, YAxis} from "recharts";
import {useStats} from "@/hooks/useStats";
import {Card, CardContent, CardHeader, CardTitle} from "@/components/ui/card";

const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div
                className="p-2 rounded-lg"
                style={{
                    backgroundColor: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    color: "hsl(var(--popover-foreground))",
                }}
            >
                <p className="label">{`${label} : ${payload[0].value.toLocaleString('de-DE')} packets dropped`}</p>
            </div>
        );
    }

    return null;
};


export function FloodChart() {
    const { data: stats } = useStats();

    const c = stats?.flood_counters;
    const chartData = stats ? [
        { name: "TCP SYN",   value: c?.tcp_syn_flood_dropped || 0, color: "#06b6d4" },
        { name: "ICMP",      value: c?.icmp_flood_dropped    || 0, color: "#ffd500" },
        { name: "UDP",       value: c?.udp_flood_dropped     || 0, color: "#ff6a00" },
    ] : [];

    return (
        <Card className="flex flex-col h-full overflow-hidden">
            <CardHeader className="shrink-0 pb-2">
                <CardTitle>Kernel Drop Counters</CardTitle>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 p-6 pt-0">
                <div className="h-full w-full mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                            <XAxis dataKey="name" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                                   tickLine={false} axisLine={false} />
                            <YAxis tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                                   tickLine={false} axisLine={false}
                                   tickFormatter={(value) => new Intl.NumberFormat('de-DE').format(value as number)}
                            />
                            <Tooltip
                                cursor={{fill: 'hsl(var(--accent))', radius: 4}}
                                content={<CustomTooltip />}
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
