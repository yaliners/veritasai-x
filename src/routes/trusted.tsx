import { createFileRoute } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useTrustedSites } from "@/lib/veritas/store";
import { Plus, Search, Trash2, ShieldCheck } from "lucide-react";
import type { TrustedSite } from "@/lib/veritas/types";

export const Route = createFileRoute("/dashboard/trusted")({
  head: () => ({
    meta: [
      { title: "Trusted Sites — VeritasAI X" },
      { name: "description", content: "Manage whitelisted domains that bypass scanning." },
    ],
  }),
  component: TrustedManager,
});

function TrustedManager() {
  const [sites, setSites] = useTrustedSites();
  const [domain, setDomain] = useState("");
  const [category, setCategory] = useState("General");
  const [level, setLevel] = useState<TrustedSite["trustLevel"]>("Standard");
  const [query, setQuery] = useState("");

  const filtered = useMemo(
    () => sites.filter((s) => s.domain.toLowerCase().includes(query.toLowerCase())),
    [sites, query],
  );

  function add() {
    const clean = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!clean) return;
    setSites([{ id: `t_${Date.now()}`, domain: clean, category, trustLevel: level, addedAt: Date.now() }, ...sites]);
    setDomain("");
  }

  function remove(id: string) {
    setSites(sites.filter((s) => s.id !== id));
  }

  const levelCls: Record<TrustedSite["trustLevel"], string> = {
    Standard: "bg-muted text-muted-foreground border-border",
    High: "bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/30",
    Enterprise: "bg-cyber-success/10 text-cyber-success border-cyber-success/30",
  };

  return (
    <>
      <Topbar title="Trusted Sites Manager" subtitle="Whitelisted domains bypass all detection engines" />
      <main className="flex-1 space-y-6 p-4 lg:p-8">
        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <h2 className="mb-1 text-base font-semibold">Add Trusted Domain</h2>
          <p className="mb-4 text-xs text-muted-foreground">Domains added here become Risk: TRUSTED · Score: 0 · Trust: 100.</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[2fr_1fr_1fr_auto]">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan" />
            <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Category" className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan" />
            <select value={level} onChange={(e) => setLevel(e.target.value as TrustedSite["trustLevel"])} className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm">
              <option value="Standard">Standard</option>
              <option value="High">High</option>
              <option value="Enterprise">Enterprise</option>
            </select>
            <button onClick={add} className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyber-cyan to-primary px-4 py-2 text-sm font-semibold text-background">
              <Plus className="h-4 w-4" /> Add
            </button>
          </div>
        </section>

        <section className="glass rounded-2xl p-6 shadow-[var(--shadow-card)]">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 rounded-lg border border-border/60 bg-card/60 px-3 py-1.5">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search trusted domains…" className="w-64 bg-transparent text-xs outline-none" />
            </div>
            <p className="text-xs text-muted-foreground">{filtered.length} domain{filtered.length === 1 ? "" : "s"}</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <th className="pb-2">Domain</th>
                  <th className="pb-2">Category</th>
                  <th className="pb-2">Trust Level</th>
                  <th className="pb-2">Date Added</th>
                  <th className="pb-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => (
                  <tr key={s.id} className="border-b border-border/30 last:border-0">
                    <td className="py-3">
                      <div className="flex items-center gap-2 mono text-xs">
                        <ShieldCheck className="h-3.5 w-3.5 text-cyber-success" /> {s.domain}
                      </div>
                    </td>
                    <td className="text-xs text-muted-foreground">{s.category}</td>
                    <td>
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${levelCls[s.trustLevel]}`}>{s.trustLevel}</span>
                    </td>
                    <td className="text-xs text-muted-foreground">{new Date(s.addedAt).toLocaleDateString()}</td>
                    <td className="text-right">
                      <button onClick={() => remove(s.id)} className="inline-flex items-center gap-1 rounded-md border border-cyber-danger/40 bg-cyber-danger/10 px-2 py-1 text-[10px] font-semibold text-cyber-danger hover:bg-cyber-danger/20">
                        <Trash2 className="h-3 w-3" /> Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </>
  );
}