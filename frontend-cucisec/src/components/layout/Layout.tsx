import {Link, Outlet, useLocation} from "react-router-dom"
import {Ban, LayoutDashboard, Network, ScrollText, Shield} from "lucide-react";
import {cn} from "@/lib/utils"

export default function Layout() {
    const location = useLocation();

    const navItems = [
        {name: "Dashboard", path: "/", icon: LayoutDashboard},
        {name: "Rules", path: "/rules", icon: Shield},
        {name: "Blacklist", path: "/blacklist", icon: Ban},
        {name: "Logs", path: "/logs", icon: ScrollText},
    ];

    return (
        <div className="flex h-screen w-screen overflow-hidden bg-background">
            {/* Sidebar Layout */}
            <aside className="shrink-0 border-r border-border bg-card/50 py-6 flex flex-col h-full w-14 lg:w-64 px-2 lg:px-4">
                <div className="flex items-center gap-3 mb-10 px-1 lg:px-2">
                    <div className="bg-primary/20 p-2 rounded-lg border border-primary/30 shrink-0">
                        <Network className="w-6 h-6 text-primary"/>
                    </div>
                    <h1 className="hidden lg:block text-xl font-bold tracking-tight">CuciSec</h1>
                </div>

                {/* Routes-navigation */}
                <nav className="flex flex-col gap-2">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = location.pathname === item.path;

                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                title={item.name}
                                className={cn(
                                    "flex items-center gap-3 px-2 lg:px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 justify-center lg:justify-start",
                                    isActive
                                        ? "bg-primary text-primary-foreground shadow-md"
                                        : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                                )}
                            >
                                <Icon className="w-5 h-5 shrink-0"/>
                                <span className="hidden lg:inline">{item.name}</span>
                            </Link>
                        );
                    })}
                </nav>
            </aside>

            <main className="flex-1 p-4 lg:p-6 overflow-y-auto min-w-0">
                <div className="w-full h-full">
                    <Outlet/>
                </div>
            </main>
        </div>
    );
}