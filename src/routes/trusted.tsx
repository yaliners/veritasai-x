import { createFileRoute } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import { Topbar } from "@/components/veritas/topbar";
import { useTrustedSites } from "@/lib/veritas/store";
import { Plus, Search, Trash2, ShieldCheck } from "lucide-react";
import type { TrustedSite } from "@/lib/veritas/types";

export const Route = createFileRoute("/trusted")({
  head: () => ({
    meta: [
      { title: "Trusted Sites — VeritasShield AI" },
      { name: "description", content: "Manage whitelisted domains that bypass scanning." },
    ],
  }),
  component: TrustedManager,
});

function autoCategorize(inputDomain: string): string {
  const clean = inputDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!clean) return "General";
  
  if (clean.endsWith(".edu") || clean.endsWith(".ac.in") || clean.endsWith(".edu.in") || ["school", "college", "university", "lms", "saveetha", "canvas", "blackboard", "moodle", "coursera", "udemy", "edx", "khanacademy"].some(x => clean.includes(x))) return "Education";
  if (clean.endsWith(".gov") || clean.endsWith(".gov.in") || clean.endsWith(".nic.in") || ["government", "gov", "state", "federal", "national", "admin"].some(x => clean.includes(x))) return "Government";
  if (clean.endsWith(".org") || ["charity", "nonprofit", "ngo", "foundation", "redcross", "unicef"].some(x => clean.includes(x))) return "Non-Profit / Organization";

  const infrastructure = ["google", "microsoft", "apple", "aws", "azure", "cloudflare", "oracle", "digitalocean", "heroku", "linode", "vultr", "godaddy", "namecheap", "dns", "host"];
  const finance = ["stripe", "paypal", "bank", "visa", "mastercard", "coinbase", "chase", "fidelity", "hsbc", "wellsfargo", "citi", "capitalone", "barclays", "crypto", "binance", "robinhood", "venmo", "transferwise", "wise"];
  const dev = ["github", "gitlab", "npm", "vercel", "netlify", "stackoverflow", "jira", "bitbucket", "git", "docker", "kubernetes", "pnpm", "bun", "vite", "deno", "postman", "sentry", "datadog", "figma", "codepen", "codesandbox"];
  const ai = ["openai", "anthropic", "cohere", "gemini", "huggingface", "claude", "chatgpt", "perplexity", "midjourney", "runway", "elevenlabs", "copilot"];
  const reference = ["wikipedia", "britannica", "dictionary", "thesaurus", "wiki", "quora", "medium", "reddit", "stackexchange", "mdn", "w3schools"];
  const social = ["facebook", "instagram", "twitter", "x.com", "linkedin", "tiktok", "pinterest", "whatsapp", "telegram", "snapchat", "messenger", "discord", "slack", "zoom", "teams"];
  const entertainment = ["netflix", "spotify", "youtube", "disney", "hulu", "twitch", "hbo", "primevideo", "audible", "vimeo", "soundcloud", "crunchyroll"];
  const ecommerce = ["amazon", "ebay", "shopify", "walmart", "target", "aliexpress", "etsy", "bestbuy", "temu", "flipkart", "alibaba", "ikea", "costco"];
  const news = ["nytimes", "cnn", "bbc", "reuters", "bloomberg", "wsj", "forbes", "guardian", "huffpost", "techcrunch", "wired", "theverge", "cnet"];
  const travel = ["airbnb", "booking", "expedia", "tripadvisor", "uber", "lyft", "grab", "trip", "kayak", "flight"];
  
  if (infrastructure.some(x => clean.includes(x))) return "Infrastructure";
  if (finance.some(x => clean.includes(x))) return "Finance";
  if (dev.some(x => clean.includes(x))) return "Development";
  if (ai.some(x => clean.includes(x))) return "AI";
  if (reference.some(x => clean.includes(x))) return "Reference";
  if (social.some(x => clean.includes(x))) return "Social Media";
  if (entertainment.some(x => clean.includes(x))) return "Entertainment";
  if (ecommerce.some(x => clean.includes(x))) return "E-Commerce";
  if (news.some(x => clean.includes(x))) return "News";
  if (travel.some(x => clean.includes(x))) return "Travel";
  
  return "General";
}

function TrustedManager() {
  const [sites, setSites] = useTrustedSites();
  const [domain, setDomain] = useState("");
  const [category, setCategory] = useState("General");
  const [isManualCategory, setIsManualCategory] = useState(false);
  const [level, setLevel] = useState<TrustedSite["trustLevel"]>("Standard");
  const [query, setQuery] = useState("");

  const filtered = useMemo(
    () => sites.filter((s) => s.domain.toLowerCase().includes(query.toLowerCase())),
    [sites, query],
  );

  const handleDomainChange = (val: string) => {
    setDomain(val);
    if (!isManualCategory) {
      setCategory(autoCategorize(val));
    }
  };

  const handleCategoryChange = (val: string) => {
    setCategory(val);
    setIsManualCategory(true);
  };

  function add() {
    const clean = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!clean) return;
    setSites([{ id: `t_${Date.now()}`, domain: clean, category, trustLevel: level, addedAt: Date.now() }, ...sites]);
    setDomain("");
    setCategory("General");
    setIsManualCategory(false);
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
            <input value={domain} onChange={(e) => handleDomainChange(e.target.value)} placeholder="example.com" className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan" />
            <input value={category} onChange={(e) => handleCategoryChange(e.target.value)} placeholder="Category" className="rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-sm outline-none focus:border-cyber-cyan" />
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