import {CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis} from "recharts";
import {useLogCounts} from "@/hooks/useStats.ts";
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from "@/components/ui/card.tsx";

export function TrafficChart() {
    const {data = [], isLoading, isError} = useLogCounts();

    return (
        <Card className="col-span-1 lg:col-span-2 flex flex-col h-full overflow-hidden">
            <CardHeader className="shrink-0 pb-2">
                <CardTitle>Traffic (Last 30 Minutes)</CardTitle>
                <CardDescription>Accepted vs Dropped Packets</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 p-6 pt-0">
                {isLoading ? (
                    <div className="h-full flex items-center justify-center text-muted-foreground">
                        Data is loading...
                    </div>
                ) : isError ? (
                    <div className="h-full flex items-center justify-center text-destructive">
                        Error at data loading. Verify backend connection.
                    </div>
                ) : data.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-muted-foreground">
                        No existing traffic.
                    </div>
                ) : (
                    <div className="h-full w-full mt-2">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={data} margin={{top: 5, right: 20, bottom: 5, left: 0}}>
                                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.4}
                                               vertical={false}/>
                                <XAxis dataKey="minute" tick={{fontSize: 12, fill: "hsl(var(--muted-foreground))"}}
                                       stroke="hsl(var(--border))" tickLine={false} axisLine={false}/>
                                <YAxis tick={{fontSize: 12, fill: "hsl(var(--muted-foreground))"}}
                                       stroke="hsl(var(--border))" tickLine={false} axisLine={false}/>
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: "hsl(var(--popover))",
                                        borderColor: "hsl(var(--border))",
                                        borderRadius: "0.5rem"
                                    }}
                                    itemStyle={{color: "hsl(var(--foreground))"}}
                                    labelStyle={{fontWeight: "bold", marginBottom: "4px"}}
                                />
                                <Line type="monotone" dataKey="accepted" name="Accepted" stroke="hsl(var(--success))"
                                      strokeWidth={3} dot={{r: 4, fill: "hsl(var(--success))", strokeWidth: 0}}
                                      activeDot={{r: 6, fill: "hsl(var(--success))"}}/>
                                <Line type="monotone" dataKey="dropped" name="Dropped" stroke="hsl(var(--destructive))"
                                      strokeWidth={3} dot={{r: 4, fill: "hsl(var(--destructive))", strokeWidth: 0}}
                                      activeDot={{r: 6, fill: "hsl(var(--destructive))"}}/>
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}