import { Shield } from 'lucide-react';
import type { LegalDocument } from './LegalCenter';

export default function Footer({ onOpenPolicy }: { onOpenPolicy: (policy: LegalDocument) => void }) {
  const policies: [string, LegalDocument][] = [['Privacy', 'privacy'], ['Terms', 'terms'], ['Cookies', 'cookies'], ['Security', 'security'], ['Acceptable use', 'acceptable-use'], ['EULA', 'eula'], ['DPA', 'data-processing']];
  return (
    <footer className="border-t border-[rgba(255,255,255,0.05)] bg-[rgba(3,5,8,0.9)] py-10 relative z-10">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-5">
          <div className="flex items-center gap-2 opacity-50 hover:opacity-100 transition-opacity"><Shield className="w-5 h-5 text-white" /><span className="text-sm font-bold tracking-[2px] text-white">AEGIS XII</span></div>
          <nav aria-label="Legal policies" className="flex flex-wrap justify-center gap-x-4 gap-y-2">{policies.map(([label, policy]) => <button key={policy} onClick={() => onOpenPolicy(policy)} className="text-xs text-[#8b9bb4] hover:text-[#00e5ff] transition-colors">{label}</button>)}</nav>
          <p className="text-xs text-[#8b9bb4]">&copy; {new Date().getFullYear()} ASD Solutions · Enterprise Security Division</p>
        </div>
        <p className="mt-6 text-center text-[11px] text-[#61718a]">Security tools support your defences but do not guarantee prevention of all threats.</p>
      </div>
    </footer>
  );
}
