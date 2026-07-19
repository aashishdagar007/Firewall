

const METRICS = [
  { label: 'Total Packets', value: '1,204,550', trend: '▲ 450', trendType: 'up', unit: 'packets/sec' },
  { label: 'Bandwidth', value: '4.2 GB', trend: 'Total payload processed', trendType: 'neutral', unit: '', color: 'text-[#00e5ff]' },
  { label: 'Threats Blocked', value: '342', trend: '▼ 2', trendType: 'down', unit: 'blocked/sec', color: 'text-[#ff3355]' },
  { label: 'Clean Traffic', value: '99.9%', trend: 'Packets safely routed', trendType: 'neutral', unit: '', color: 'text-[#00e676]' }
];

export default function MetricCards() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
      {METRICS.map((metric, i) => (
        <div key={i} className="glass-card flex flex-col">
          <div className="flex justify-between items-start">
            <div className="text-[11px] font-semibold text-[#8b9bb4] uppercase tracking-[1.2px]">{metric.label}</div>
            <div className="w-20 h-9 bg-white/5 rounded-md"></div>
          </div>
          <div className={`font-mono text-3xl font-bold mt-2 leading-none ${metric.color || 'text-white'}`}>
            {metric.value}
          </div>
          <div className="text-[11px] mt-1.5 flex items-center gap-1 text-[#8b9bb4]">
            {metric.trendType !== 'neutral' && (
              <span className={metric.trendType === 'up' ? 'text-[#00e676]' : 'text-[#ff3355]'}>
                {metric.trend}
              </span>
            )}
            {metric.trendType === 'neutral' && metric.trend}
            {metric.unit && <span>{metric.unit}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}
