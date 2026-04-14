import {AddRuleModal} from "@/components/rules/AddRuleModal.tsx";
import {RulesTable} from "@/components/rules/RulesTable.tsx";

export default function RulesPage() {
    return (
        <div className="space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Firewall Rules</h1>
                    <p className="text-muted-foreground">
                        Manage packet filtering rules. Changes apply instantly to nftables.
                    </p>
                </div>
                <AddRuleModal/>
            </div>

            <RulesTable/>
        </div>

    )
}