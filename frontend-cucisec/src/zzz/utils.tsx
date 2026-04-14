import {Loader2, ServerCrash} from "lucide-react";

export const PageLoader = () => (
    <div className="flex h-[50vh] w-full items-center justify-center">
        <div className="flex items-center gap-3 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin"/>
            <span className="animate-pulse">Loading module...</span>
        </div>
    </div>
);

interface ErrorFallbackProps {
    error: unknown;
    resetErrorBoundary: () => void;
}

export const ErrorFallback = ({error, resetErrorBoundary}: ErrorFallbackProps) => (
    <div className="flex h-[50vh] flex-col items-center justify-center gap-4 text-destructive">
        <ServerCrash className="h-12 w-12"/>
        <h2 className="text-xl font-bold">Something didn't worked</h2>
        <p className="text-muted-foreground">
            {error instanceof Error ? error.message : 'An unexpected error occurred'}
        </p>
        <button
            onClick={resetErrorBoundary}
            className="mt-4 rounded-md bg-primary px-4 py-2 text-primary-foreground hover:bg-primary/90"
        >
            Try again
        </button>
    </div>
)
