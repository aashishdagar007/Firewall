

const mockFeed = [
  { id: 1, type: 'allow', route: '192.168.1.100:443 -> 142.250.190.46:443', process: 'chrome.exe', time: '10:32:45.102' },
  { id: 2, type: 'block', route: '192.168.1.100:445 -> 10.0.0.5:445', process: 'SYSTEM', time: '10:32:45.050' },
  { id: 3, type: 'allow', route: '192.168.1.100:53 -> 8.8.8.8:53', process: 'svchost.exe', time: '10:32:44.900' },
  { id: 4, type: 'allow', route: '192.168.1.100:80 -> 93.184.216.34:80', process: 'curl.exe', time: '10:32:44.820' },
  { id: 5, type: 'block', route: '192.168.1.100:3389 -> 45.33.32.156:3389', process: 'Unknown', time: '10:32:44.100' },
];

export default function LiveFeed() {
  return (
    <div className="glass-card flex flex-col flex-1 h-full">
      <div className="text-xs font-semibold text-[#8b9bb4] uppercase tracking-[1.5px] mb-4 flex items-center gap-2">
        <span className="text-[#00e5ff]">◈</span> Live Packet Feed
      </div>
      
      <div className="flex gap-2 mb-3 shrink-0 flex-wrap">
        <input 
          type="text" 
          placeholder="Filter IPs, processes..." 
          className="flex-1 min-w-[120px] bg-black/30 border border-[rgba(0,229,255,0.15)] rounded-md px-2.5 py-1.5 text-white font-mono text-[11px] outline-none focus:border-[#00e5ff]"
        />
        <button className="px-2.5 py-1 rounded-md border border-[rgba(0,229,255,0.3)] bg-[rgba(0,229,255,0.1)] text-[#00e5ff] text-[11px] transition-all">All</button>
        <button className="px-2.5 py-1 rounded-md border border-white/5 bg-white/5 text-[#8b9bb4] text-[11px] hover:bg-white/10 hover:text-white transition-all">Blocked</button>
      </div>

      <div className="flex flex-col gap-2 flex-1 overflow-y-auto pr-1">
        {mockFeed.map((item) => (
          <div 
            key={item.id} 
            className={`grid grid-cols-[32px_1fr_auto] gap-3 items-center bg-black/30 px-3.5 py-2.5 rounded-lg border-l-2 ${
              item.type === 'allow' ? 'border-[#00e676]' : 'border-[#ff3355] bg-[rgba(255,51,85,0.04)]'
            }`}
          >
            <div className={`w-8 h-8 rounded-md flex items-center justify-center text-[10px] font-bold font-mono ${
              item.type === 'allow' ? 'bg-[rgba(0,230,118,0.12)] text-[#00e676]' : 'bg-[rgba(255,51,85,0.12)] text-[#ff3355]'
            }`}>
              {item.type === 'allow' ? 'OK' : 'DROP'}
            </div>
            <div className="flex flex-col gap-1 min-w-0">
              <div className="font-mono text-[11px] text-white truncate">{item.route}</div>
              <div className="text-[10px] text-[#8b9bb4] flex gap-2">
                <span className="text-[#00e5ff]">{item.process}</span>
              </div>
            </div>
            <div className="text-[10px] text-[#8b9bb4] font-mono whitespace-nowrap">
              {item.time}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
