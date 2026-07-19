

export default function Header() {
  return (
    <header className="h-[72px] flex justify-between items-center px-8 bg-gradient-to-r from-[rgba(12,16,26,0.9)] to-[rgba(12,16,26,0.4)] border-b border-[rgba(255,255,255,0.05)] backdrop-blur-md shrink-0 z-10">
      <div className="flex items-center gap-5">
        <div>
          <div className="text-[22px] font-bold tracking-[2px] bg-gradient-to-br from-white to-[#00e5ff] text-transparent bg-clip-text">AEGIS XII</div>
          <div className="text-[11px] font-medium text-[#8b9bb4] tracking-[2px] uppercase mt-0.5">Kernel Firewall</div>
        </div>
        <div className="px-3 py-1.5 rounded-full text-[10px] font-mono tracking-wide bg-[rgba(0,229,255,0.07)] border border-[rgba(0,229,255,0.2)] text-[#8b9bb4]">
          OBSERVER
        </div>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <button className="px-3.5 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-wide bg-[rgba(255,51,85,0.12)] text-[#ff3355] border border-[rgba(255,51,85,0.3)] hover:bg-[#ff3355] hover:text-white hover:shadow-[0_0_20px_rgba(255,51,85,0.35)] transition-all">
            ⛔ Block All
          </button>
          <button className="px-3.5 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-wide bg-[rgba(0,230,118,0.1)] text-[#00e676] border border-[rgba(0,230,118,0.25)] hover:bg-[#00e676] hover:text-black hover:shadow-[0_0_20px_rgba(0,230,118,0.35)] transition-all">
            ✅ Allow All
          </button>
        </div>
        
        <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full border border-[rgba(0,229,255,0.25)] bg-[rgba(0,229,255,0.05)] cursor-pointer">
          <div className="w-9 h-5 rounded-full bg-[#00e5ff] shadow-[0_0_10px_rgba(0,229,255,0.5)] relative">
            <div className="absolute top-[3px] left-[3px] w-[13px] h-[13px] bg-white rounded-full translate-x-[17px] transition-transform" />
          </div>
          <span className="text-[11px] font-bold tracking-[0.8px] uppercase text-[#00e5ff]">🛡 Stealth</span>
        </div>

        <div className="flex items-center gap-2 px-3.5 py-1.5 bg-[rgba(0,230,118,0.08)] border border-[rgba(0,230,118,0.25)] rounded-full text-[11px] font-bold text-[#00e676] tracking-[1.2px] uppercase">
          <div className="w-2 h-2 bg-[#00e676] rounded-full shadow-[0_0_8px_#00e676] animate-pulse" />
          Active
        </div>
      </div>
    </header>
  );
}
