import {useState} from "react";
import {useForm} from "react-hook-form";
import {zodResolver} from "@hookform/resolvers/zod";
import * as z from "zod";
import {useMutation, useQueryClient} from "@tanstack/react-query";
import {toast} from "sonner";
import {Plus} from "lucide-react";

import {api} from "@/api/client.ts";
import {Button} from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import {Form, FormControl, FormField, FormItem, FormLabel, FormMessage,} from "@/components/ui/form";
import {Input} from "@/components/ui/input";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue,} from "@/components/ui/select";


// validation schema
const formSchema = z.object({
    ip_src: z.string().optional(),
    port: z.string().optional(),
    protocol: z.string(),
    action: z.enum(["ACCEPT", "DROP"]),
    description: z.string().optional(),
    zone: z.string(),
});

export function AddRuleModal() {
    const [open, setOpen] = useState(false);
    const queryClient = useQueryClient();

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            ip_src: "",
            port: "",
            protocol: "ALL",
            action: "DROP",
            description: "",
            zone: "WAN",
        },
    });


    const addRuleMutation = useMutation({
        mutationFn: api.addRule,
        onSuccess: async () => {
            await queryClient.invalidateQueries({queryKey: ["rules"]}); // refresh table
            toast.success("Rule added successfully!");
            setOpen(false);
            form.reset();
        },
        onError: () => {
            toast.error("Failed to add rule. Check connection.");
        },
    });


    function onSubmit(values: z.infer<typeof formSchema>) {
        const finalRuleData = {
            ip_src: !values.ip_src || values.ip_src.trim() === "" ? null : values.ip_src,
            port: values.port ? Number(values.port) : null,
            protocol: values.protocol === "ALL" ? null : values.protocol,
            action: values.action,
            description: !values.description || values.description.trim() === "" ? null : values.description,
            enabled: 1,
            zone: values.zone,
        };

        addRuleMutation.mutate(finalRuleData);
    }


    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
                    <Plus className="mr-2 h-4 w-4"/> Add New Rule
                </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-106.25">
                <DialogHeader>
                    <DialogTitle>Add Firewall Rule</DialogTitle>
                    <DialogDescription>
                        Create a new packet filtering rule for nftables.
                    </DialogDescription>
                </DialogHeader>

                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <FormField
                                control={form.control}
                                name="action"
                                render={({field}) => (
                                    <FormItem>
                                        <FormLabel>Action</FormLabel>
                                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                                            <FormControl>
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Select action"/>
                                                </SelectTrigger>
                                            </FormControl>
                                            <SelectContent>
                                                <SelectItem value="ACCEPT">ACCEPT</SelectItem>
                                                <SelectItem value="DROP">DROP</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </FormItem>
                                )}
                            />
                            <FormField
                                control={form.control}
                                name="protocol"
                                render={({field}) => (
                                    <FormItem>
                                        <FormLabel>Protocol</FormLabel>
                                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                                            <FormControl>
                                                <SelectTrigger>
                                                    <SelectValue placeholder="Select protocol"/>
                                                </SelectTrigger>
                                            </FormControl>
                                            <SelectContent>
                                                <SelectItem value="ALL">ALL</SelectItem>
                                                <SelectItem value="TCP">TCP</SelectItem>
                                                <SelectItem value="UDP">UDP</SelectItem>
                                                <SelectItem value="ICMP">ICMP</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </FormItem>
                                )}
                            />
                        </div>

                        <FormField
                            control={form.control}
                            name="ip_src"
                            render={({field}) => (
                                <FormItem>
                                    <FormLabel>Source IP (Optional)</FormLabel>
                                    <FormControl>
                                        <Input placeholder="e.g. 192.168.1.50 or empty for any" {...field} />
                                    </FormControl>
                                    <FormMessage/>
                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="port"
                            render={({field}) => (
                                <FormItem>
                                    <FormLabel>Destination Port (Optional)</FormLabel>
                                    <FormControl>
                                        <Input type="text" placeholder="e.g. 80 or empty for any" {...field} />
                                    </FormControl>
                                    <FormMessage/>
                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="description"
                            render={({field}) => (
                                <FormItem>
                                    <FormLabel>Description</FormLabel>
                                    <FormControl>
                                        <Input placeholder="Why is this rule here?" {...field} />
                                    </FormControl>
                                    <FormMessage/>
                                </FormItem>
                            )}
                        />

                        <Button type="submit" className="w-full" disabled={addRuleMutation.isPending}>
                            {addRuleMutation.isPending ? "Adding..." : "Save Rule"}
                        </Button>
                    </form>
                </Form>
            </DialogContent>
        </Dialog>
    );
}