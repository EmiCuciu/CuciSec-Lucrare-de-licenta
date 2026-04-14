import {BrowserRouter, Route, Routes} from "react-router-dom";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {Toaster} from "sonner";
import {Suspense} from "react";
import {ErrorBoundary} from "react-error-boundary";

import Layout from "@/components/layout/Layout.tsx";
import DashboardPage from "@/pages/DashboardPage.tsx";
import RulesPage from "@/pages/RulePage.tsx";
import LogsPage from "@/pages/LogsPage.tsx";
import BlacklistPage from "@/pages/BlacklistPage.tsx";
import {ErrorFallback, PageLoader} from "@/zzz/utils.tsx";

const queryClient = new QueryClient();

export default function App() {
    return (
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                <Routes>
                    <Route path="/" element={<Layout/>}>
                        <Route index element={
                            <ErrorBoundary FallbackComponent={ErrorFallback}>
                                <Suspense fallback={<PageLoader/>}><DashboardPage/></Suspense>
                            </ErrorBoundary>
                        }/>
                        <Route path="rules" element={
                            <ErrorBoundary FallbackComponent={ErrorFallback}>
                                <Suspense fallback={<PageLoader/>}><RulesPage/></Suspense>
                            </ErrorBoundary>
                        }/>
                        <Route path="logs" element={
                            <ErrorBoundary FallbackComponent={ErrorFallback}>
                                <Suspense fallback={<PageLoader/>}><LogsPage/></Suspense>
                            </ErrorBoundary>
                        }/>
                        <Route path="blacklist" element={
                            <ErrorBoundary FallbackComponent={ErrorFallback}>
                                <Suspense fallback={<PageLoader/>}><BlacklistPage/></Suspense>
                            </ErrorBoundary>
                        }/>
                    </Route>
                </Routes>
            </BrowserRouter>

            <Toaster richColors theme="dark" position="top-right"/>
        </QueryClientProvider>
    );
}