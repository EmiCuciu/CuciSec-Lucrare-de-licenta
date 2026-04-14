import {CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis} from "recharts";
import {useLogCounts} from "@/hooks/useStats.ts";
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from "@/components/ui/card.tsx";

export function TrafficChart() {
    const {data = [], isLoading, isError} = useLogCounts();

    return (
        <Card className="col-span-1 lg:col-span-2">
            <CardHeader>
                <CardTitle>Traffic (Last 30 Minutes)</CardTitle>
                <CardDescription>Accepted vs Dropped Packets</CardDescription>
            </CardHeader>
            <CardContent>
                {isLoading ? (
                    <div className="h-62.5 flex items-center justify-center text-muted-foreground">
                        Data is loading...
                    </div>
                ) : isError ? (
                    <div className="h-62.5 flex items-center justify-center text-muted-foreground">
                        Error at data loading. Verify backend connection.
                    </div>
                ) : data.length === 0 ? (
                    <div className="h-62.5 flex items-center justify-center text-muted-foreground">
                        No existing traffic.
                    </div>
                ) : (
                    <div className="h-62.5 w-full mt-4">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={data} margin={{
                                top: 5,
                                right: 20,
                                bottom: 5,
                                left: 0
                            }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.4}
                                               vertical={false}/>
                                <XAxis
                                    dataKey="minutes"
                                    tick={{fontSize: 12, fill: "hsl(var(--muted-foreground))"}}
                                    stroke="hsl(var(--border))"
                                    tickLine={false}
                                    axisLine={false}
                                />
                                <YAxis
                                    tick={{fontSize: 12, fill: "hsl(var(--muted-foreground))"}}
                                    stroke="hsl(var(--border))"
                                    tickLine={false}
                                    axisLine={false}
                                />
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: "hsl(var(--popover))",
                                        borderColor: "hsl(var(--border))",
                                        borderRadius: "0.5rem"
                                    }}
                                    itemStyle={{color: "hsl(var(--foreground))"}}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="accepted"
                                    name="Accepted"
                                    stroke="hsl(var(--success))"
                                    strokeWidth={3}
                                    dot={false}
                                    activeDot={{r: 6, fill: "hsl(var(--success))"}}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="dropped"
                                    name="Dropped"
                                    stroke="hsl(var(--destructive))"
                                    strokeWidth={3}
                                    dot={false}
                                    activeDot={{r: 6, fill: "hsl(var(--destructive))"}}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}