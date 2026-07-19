export default function StatsBar() {
  return (
    <div className="relative border-y border-[rgba(255,255,255,0.05)] bg-[rgba(12,16,26,0.6)] backdrop-blur-md z-10 py-8">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 md:gap-0 divide-x-0 md:divide-x divide-[rgba(255,255,255,0.05)]">
          <div className="flex flex-col items-center justify-center text-center px-4">
            <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">
              99<span className="text-[#00e5ff] text-2xl">%</span>
            </div>
            <div className="text-xs uppercase tracking-widest text-[#8b9bb4] font-semibold">Threat Detection Rate</div>
          </div>
          
          <div className="flex flex-col items-center justify-center text-center px-4">
            <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">
              &lt;1<span className="text-[#00e5ff] text-2xl">ms</span>
            </div>
            <div className="text-xs uppercase tracking-widest text-[#8b9bb4] font-semibold">Processing Latency</div>
          </div>
          
          <div className="flex flex-col items-center justify-center text-center px-4">
            <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">
              7
            </div>
            <div className="text-xs uppercase tracking-widest text-[#8b9bb4] font-semibold">OSI Layers Monitored</div>
          </div>
          
          <div className="flex flex-col items-center justify-center text-center px-4">
            <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">
              100<span className="text-[#00e5ff] text-2xl">%</span>
            </div>
            <div className="text-xs uppercase tracking-widest text-[#8b9bb4] font-semibold">Local Execution</div>
          </div>
        </div>
      </div>
    </div>
  );
}
