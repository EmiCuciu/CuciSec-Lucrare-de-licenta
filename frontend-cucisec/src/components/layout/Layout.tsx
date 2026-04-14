import {Link, Outlet, useLocation} from "react-router-dom"
import {Ban, LayoutDashboard, ScrollText, Shield} from "lucide-react";
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
        <div className="flex min-h-screen bg-background">
            {/* Sidebar Layout */}
            <aside className="w-64 border-r border-border bg-card/50 px-4 py-6 flex flex-col">
                <div className="flex items-center gap-3 mb-10 px-2">
                    <div className="bg-primary/20 p-2 rounded-lg border border-primary/30">
                        <Shield className="w-6 h-6 text-primary"/>
                    </div>
                    <h1 className="text-xl font-bold tracking-tight">CuciSec</h1>
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
                                className={cn(
                                    "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200",
                                    isActive
                                        ? "bg-primary text-primary-foreground shadow-md"
                                        : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                                )}
                            >
                                <Icon className="w-5 h-5"/>
                                {item.name}
                            </Link>
                        );
                    })}
                </nav>
            </aside>

            { /* Main Content */}
            <main className="flex-1 p-8 overflow-y-auto">
                <div className="max-w-6xl mx-auto">
                    <Outlet/>
                </div>
            </main>
        </div>
    );
}