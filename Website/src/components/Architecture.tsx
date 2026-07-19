export default function Architecture() {
  return (
    <section id="architecture" className="py-24 relative overflow-hidden bg-[rgba(10,14,22,0.5)]">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          
          {/* Visual Side */}
          <div className="glass-card p-8 h-[400px] flex flex-col justify-center items-center relative border border-[rgba(255,255,255,0.1)]">
            <div className="text-xs uppercase tracking-widest text-[#8b9bb4] mb-8 font-semibold text-center w-full">Live Packet Flow</div>
            
            <div className="flex justify-between items-center w-full max-w-sm relative">
              <div className="flex flex-col items-center">
                <div className="text-[10px] text-[#8b9bb4] mb-4 tracking-widest">INBOUND</div>
                <div className="w-2 h-2 rounded-full bg-[#3b82f6] shadow-[0_0_10px_#3b82f6] animate-[pulse_1s_infinite]" />
                <div className="w-2 h-2 rounded-full bg-[#ff3355] shadow-[0_0_10px_#ff3355] mt-4 animate-[pulse_1.5s_infinite]" />
                <div className="w-2 h-2 rounded-full bg-[#3b82f6] shadow-[0_0_10px_#3b82f6] mt-4 animate-[pulse_2s_infinite]" />
              </div>
              
              <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-[#00e5ff]/20 to-[#3b82f6]/20 border border-[#00e5ff]/50 flex items-center justify-center relative shadow-[0_0_30px_rgba(0,229,255,0.2)] z-10 backdrop-blur-md">
                <div className="absolute inset-0 rounded-2xl border border-[#00e5ff] animate-[ping_2s_cubic-bezier(0,0,0.2,1)_infinite] opacity-20" />
                <span className="text-white font-bold text-xs uppercase tracking-widest text-center">DPI<br/>Engine</span>
              </div>
              
              <div className="flex flex-col items-center">
                <div className="text-[10px] text-[#8b9bb4] mb-4 tracking-widest">OUTBOUND</div>
                <div className="w-2 h-2 rounded-full bg-[#00e676] shadow-[0_0_10px_#00e676] animate-[pulse_1s_infinite]" />
                <div className="w-2 h-2 rounded-full bg-[#00e676] shadow-[0_0_10px_#00e676] mt-4 animate-[pulse_1.5s_infinite]" />
                <div className="w-2 h-2 rounded-full bg-[rgba(255,255,255,0.1)] mt-4 flex items-center justify-center relative"><div className="absolute w-4 h-px bg-[#ff3355] rotate-45" /><div className="absolute w-4 h-px bg-[#ff3355] -rotate-45" /></div>
              </div>

              {/* Connecting lines */}
              <div className="absolute top-1/2 left-[20%] right-[20%] h-px bg-gradient-to-r from-transparent via-[#00e5ff]/50 to-transparent -translate-y-1/2 -z-10" />
            </div>

            <div className="mt-auto flex justify-center gap-6 text-[10px] uppercase tracking-wider font-semibold text-[#8b9bb4]">
              <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-[#00e676]" />Allowed</span>
              <span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-[#ff3355]" />Blocked</span>
            </div>
          </div>

          {/* Text Side */}
          <div className="flex flex-col items-start">
            <div className="inline-block px-3 py-1 rounded-full border border-[rgba(255,255,255,0.1)] bg-[rgba(255,255,255,0.02)] text-xs font-bold tracking-widest uppercase text-[#8b9bb4] mb-4">
              Architecture
            </div>
            <h2 className="text-4xl font-bold mb-6">Raw Socket Interception</h2>
            <p className="text-[#8b9bb4] text-lg leading-relaxed mb-6">
              AEGIS XII bypasses standard user-space APIs. By hooking directly into the network adapter at the lowest system level, it acts as the final gatekeeper for all inbound and outbound traffic.
            </p>
            <p className="text-[#8b9bb4] text-lg leading-relaxed mb-8">
              A completely silent background service is paired with a native frameless dashboard that visualizes network flow in real-time.
            </p>
            
            <div className="flex flex-wrap gap-3">
              {['WinSock2', 'Raw Sockets', 'WinDivert', 'Zero-Copy'].map(tag => (
                <span key={tag} className="px-4 py-2 rounded-lg bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.05)] text-sm font-mono text-[#e2e8f0]">
                  {tag}
                </span>
              ))}
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
