import {Card, CardContent, CardHeader, CardTitle} from "@/components/ui/card"
import {cn} from "@/lib/utils.ts";

interface MetricCardProps {
    title: string;
    value: string | number;
    icon: React.ReactNode;
    trend?: string;
    variant?: "default" | "success" | "danger" | "warning" | "info";
    className?: string;
}

export function MetricCard({
                               title, value, icon, trend, variant = "default", className,
                           }: MetricCardProps) {
    const variantStyles = {
        default: "card-stat-default text-foreground",
        success: "card-stat-succes text-success",
        danger: "card-stat-danger text-destructive",
        warning: "card-stat-warning text-warning",
        info: "bg-info/10 text-info",
    };

    return (
        <Card className={cn("overflow-hidden border-border/50", variantStyles[variant], className)}>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                <CardTitle className="text-sm font-medium opacity-80">{title}</CardTitle>
                <div className="opacity-80">{icon}</div>
            </CardHeader>
            <CardContent>
                <div className="text-2xl font-bold">{value}</div>
                {trend && (
                    <p className="text-xs mt-1 opacity-70">{trend}</p>
                )}
            </CardContent>
        </Card>
    );
}