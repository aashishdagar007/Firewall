import { Activity, ShieldAlert, Wifi, Cpu, Link } from 'lucide-react';

export default function PlatformFeatures() {
  return (
    <section id="platform" className="py-24 relative">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <div className="inline-block px-3 py-1 rounded-full border border-[rgba(255,255,255,0.1)] bg-[rgba(255,255,255,0.02)] text-xs font-bold tracking-widest uppercase text-[#8b9bb4] mb-4">
            Platform
          </div>
          <h2 className="text-4xl font-bold mb-4">Comprehensive Defense</h2>
          <p className="text-[#8b9bb4] max-w-2xl mx-auto">Every module intercepts threats before they reach the OS layer, using a seamless native architecture.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Large Card: DPI */}
          <div className="md:col-span-2 glass-card p-8 flex flex-col justify-between group hover:border-[rgba(0,229,255,0.3)]">
            <div className="absolute inset-0 bg-gradient-to-br from-[#00e5ff]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="w-12 h-12 rounded-xl bg-[rgba(0,229,255,0.1)] border border-[rgba(0,229,255,0.2)] flex items-center justify-center mb-6 text-[#00e5ff] shadow-[0_0_15px_rgba(0,229,255,0.2)]">
                <Activity className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Deep Packet Inspection</h3>
              <p className="text-[#8b9bb4] leading-relaxed max-w-md">Evaluate traffic payloads in real-time. The DPI engine inspects application-layer data to identify and drop zero-day exploits and malware signatures instantly.</p>
            </div>
          </div>

          {/* DNS Firewall */}
          <div className="glass-card p-8 group hover:border-[rgba(168,85,247,0.3)]">
            <div className="absolute inset-0 bg-gradient-to-br from-[#a855f7]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="w-12 h-12 rounded-xl bg-[rgba(168,85,247,0.1)] border border-[rgba(168,85,247,0.2)] flex items-center justify-center mb-6 text-[#a855f7] shadow-[0_0_15px_rgba(168,85,247,0.2)]">
                <Wifi className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">DNS Firewall</h3>
              <p className="text-[#8b9bb4] leading-relaxed">Intercepts and blocks outbound requests to malicious or unverified domains before they resolve.</p>
            </div>
          </div>

          {/* MAC Watchdog */}
          <div className="glass-card p-8 group hover:border-[rgba(0,230,118,0.3)]">
            <div className="absolute inset-0 bg-gradient-to-br from-[#00e676]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="w-12 h-12 rounded-xl bg-[rgba(0,230,118,0.1)] border border-[rgba(0,230,118,0.2)] flex items-center justify-center mb-6 text-[#00e676] shadow-[0_0_15px_rgba(0,230,118,0.2)]">
                <Cpu className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">MAC Watchdog</h3>
              <p className="text-[#8b9bb4] leading-relaxed">Monitors layer-2 traffic to detect and halt ARP spoofing and man-in-the-middle attacks.</p>
            </div>
          </div>

          {/* Auto Ban */}
          <div className="glass-card p-8 group hover:border-[rgba(255,140,0,0.3)]">
            <div className="absolute inset-0 bg-gradient-to-br from-[#ff8c00]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="w-12 h-12 rounded-xl bg-[rgba(255,140,0,0.1)] border border-[rgba(255,140,0,0.2)] flex items-center justify-center mb-6 text-[#ff8c00] shadow-[0_0_15px_rgba(255,140,0,0.2)]">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Autonomous Banning</h3>
              <p className="text-[#8b9bb4] leading-relaxed">Built-in heuristics detect port scans and floods. Threats are auto-isolated without intervention.</p>
            </div>
          </div>

          {/* Chain Ledger */}
          <div className="glass-card p-8 group hover:border-[rgba(59,130,246,0.3)] md:col-span-1">
            <div className="absolute inset-0 bg-gradient-to-br from-[#3b82f6]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="relative z-10">
              <div className="w-12 h-12 rounded-xl bg-[rgba(59,130,246,0.1)] border border-[rgba(59,130,246,0.2)] flex items-center justify-center mb-6 text-[#3b82f6] shadow-[0_0_15px_rgba(59,130,246,0.2)]">
                <Link className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-white">Tamper-Proof Ledger</h3>
              <p className="text-[#8b9bb4] leading-relaxed">Every firewall event is committed to a cryptographic hash-chain. No log can be silently altered.</p>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
