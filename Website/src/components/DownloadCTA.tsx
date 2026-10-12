import { Download, Check, ChevronRight } from 'lucide-react';
import DownloadConsent from './DownloadConsent';
import type { LegalDocument } from './LegalCenter';

export default function DownloadCTA({ onOpenPolicy }: { onOpenPolicy: (policy: LegalDocument) => void }) {
  return (
    <section id="download" className="py-24 relative overflow-hidden">
      <div className="max-w-4xl mx-auto px-6 relative z-10">
        <div className="glass-card p-12 text-center flex flex-col items-center border border-[rgba(0,229,255,0.3)] bg-gradient-to-br from-[rgba(0,229,255,0.05)] to-transparent relative overflow-hidden">
          {/* Animated glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[80%] h-[300px] bg-[#00e5ff] rounded-full blur-[150px] opacity-10 pointer-events-none" />
          
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[rgba(0,229,255,0.3)] bg-[rgba(0,229,255,0.1)] text-[#00e5ff] text-xs font-bold tracking-wider mb-6">
            <Check className="w-4 h-4" /> v3.0 — Latest Release
          </div>
          
          <h2 className="text-4xl md:text-5xl font-bold mb-6">Download AEGIS XII</h2>
          <p className="text-lg text-[#8b9bb4] mb-8 max-w-2xl">A single self-contained installer packages the full application: firewall engine, real-time dashboard, and all configuration files.</p>

          <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-black/40 border border-white/10 mb-8 font-mono text-sm">
            <Download className="w-4 h-4 text-[#8b9bb4]" />
            <span className="text-white">AEGIS_XII_Setup_v3.exe</span>
            <span className="text-[#00e5ff]">79 MB</span>
          </div>

          <DownloadConsent onOpenPolicy={onOpenPolicy} />
          <a href="#install" className="mt-4 flex items-center gap-2 text-sm font-semibold text-[#b5c0d2] hover:text-[#00e5ff] transition-colors">
            View Install Guide <ChevronRight className="w-4 h-4" />
          </a>

          <div className="flex flex-wrap justify-center gap-x-8 gap-y-3 text-[11px] text-[#8b9bb4] font-medium tracking-wide">
            <span className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-[#00e676]" /> Windows 10 / 11 x64</span>
            <span className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-[#00e676]" /> Admin privileges required</span>
            <span className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-[#00e676]" /> 100% Local</span>
          </div>
        </div>
      </div>
    </section>
  );
}
