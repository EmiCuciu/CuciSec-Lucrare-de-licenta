import {BrowserRouter, Route, Routes} from "react-router-dom";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {Toaster} from "sonner";

import Layout from "@/components/layout/Layout.tsx";
import DashboardPage from "@/pages/DashboardPage.tsx";
import RulesPage from "@/pages/RulePage.tsx";
import LogsPage from "@/pages/LogsPage.tsx";
import BlacklistPage from "@/pages/BlacklistPage.tsx";

const queryClient = new QueryClient();

export default function App() {
    return (
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                <Routes>
                    <Route path="/" element={<Layout/>}>
                        <Route index element={<DashboardPage/>}/>
                        <Route path="rules" element={<RulesPage/>}/>
                        <Route path="logs" element={<LogsPage/>}/>
                        <Route path="blacklist" element={<BlacklistPage/>}/>
                    </Route>
                </Routes>
            </BrowserRouter>

            <Toaster richColors theme="dark" position="top-right"/>
        </QueryClientProvider>
    );
}