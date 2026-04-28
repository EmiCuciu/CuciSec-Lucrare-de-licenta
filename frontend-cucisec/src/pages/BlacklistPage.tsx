import { AddBanModal } from "@/components/blacklist/AddBanModal";
import { BlacklistTable } from "@/components/blacklist/BlacklistTable";

export default function BlacklistPage() {
    return (
        <div className="space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Blacklist</h1>
                    <p className="text-muted-foreground">Auto and manually banned IPs</p>
                </div>
                <AddBanModal />
            </div>

            <BlacklistTable />
        </div>
    );
}