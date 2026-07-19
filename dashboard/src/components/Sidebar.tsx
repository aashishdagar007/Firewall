
import { Shield, Activity, ShieldAlert, Cpu, BookOpen, Settings, LayoutDashboard } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { id: 'apps', icon: Activity, label: 'Process Monitor' },
  { id: 'rules', icon: Shield, label: 'Rule Engine' },
  { id: 'threats', icon: ShieldAlert, label: 'Threat Monitor' },
  { id: 'hardware', icon: Cpu, label: 'Hardware Security' },
  { id: 'ledger', icon: BookOpen, label: 'Chain Ledger' },
  { id: 'settings', icon: Settings, label: 'Settings' }
];

export default function Sidebar({ activeTab, setActiveTab }: { activeTab: string, setActiveTab: (t: string) => void }) {
  return (
    <aside className="w-[72px] bg-[rgba(5,7,12,0.85)] border-r border-[rgba(0,229,255,0.15)] flex flex-col items-center py-6 backdrop-blur-md z-20 shrink-0">
      <div className="mb-8">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00e5ff] to-[#3b82f6] flex items-center justify-center shadow-[0_0_20px_rgba(0,229,255,0.35)] animate-[pulse_4s_ease-in-out_infinite]">
          <Shield className="text-white w-6 h-6" />
        </div>
      </div>
      <div className="flex flex-col items-center flex-1 gap-2 w-full">
        {NAV_ITEMS.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              title={item.label}
              className={`relative w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-200 border ${
                isActive
                  ? 'text-[#00e5ff] bg-[rgba(0,229,255,0.1)] border-[rgba(0,229,255,0.3)] shadow-[inset_0_0_12px_rgba(0,229,255,0.15)]'
                  : 'text-[#8b9bb4] border-transparent hover:text-white hover:bg-[rgba(255,255,255,0.06)]'
              }`}
            >
              {isActive && (
                <div className="absolute left-[-1px] top-1/2 -translate-y-1/2 h-[55%] w-[3px] bg-[#00e5ff] rounded-r-md shadow-[0_0_20px_rgba(0,229,255,0.35)]" />
              )}
              <Icon className="w-[22px] h-[22px]" />
            </button>
          );
        })}
      </div>
    </aside>
  );
}
