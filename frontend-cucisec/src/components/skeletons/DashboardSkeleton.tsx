import {Skeleton} from "@/components/ui/skeleton";
import {Card, CardContent, CardHeader} from "@/components/ui/card";

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div>
        <Skeleton className="h-9 w-64 mb-2" />
        <Skeleton className="h-5 w-96" />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className="overflow-hidden border-border/50">
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <Skeleton className="h-4 w-32" /> {/* title card */}
              <Skeleton className="h-5 w-5 rounded-full" /> {/* icon */}
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-24 mb-2 mt-1" /> {/* number */}
              <Skeleton className="h-3 w-40" /> {/* text */}
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        <Skeleton className="h-87.5 w-full rounded-xl" />
        <Skeleton className="h-87.5 w-full rounded-xl" />
      </div>
    </div>
  );
}