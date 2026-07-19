import { Download, ShieldCheck, Monitor, HelpCircle, ShieldAlert } from 'lucide-react';

export default function InstallGuide() {
  return (
    <section id="install" className="py-24 relative bg-black/20">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <div className="inline-block px-3 py-1 rounded-full border border-[rgba(255,255,255,0.1)] bg-[rgba(255,255,255,0.02)] text-xs font-bold tracking-widest uppercase text-[#8b9bb4] mb-4">
            Installation Guide
          </div>
          <h2 className="text-4xl font-bold mb-4">Get Up & Running in Minutes</h2>
          <p className="text-[#8b9bb4] max-w-2xl mx-auto">Follow these steps to install AEGIS XII on your Windows machine. Administrator privileges are required to enable packet capture.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          
          <div className="glass-card p-6 flex flex-col group hover:border-[#3b82f6]/30">
            <div className="flex items-center gap-4 mb-4">
              <div className="text-4xl font-bold text-[rgba(255,255,255,0.05)] font-mono">01</div>
              <div className="w-10 h-10 rounded-xl bg-[rgba(59,130,246,0.1)] border border-[rgba(59,130,246,0.2)] flex items-center justify-center text-[#3b82f6] shadow-[0_0_15px_rgba(59,130,246,0.2)]">
                <Download className="w-5 h-5" />
              </div>
            </div>
            <h3 className="text-xl font-bold mb-3">Download the Installer</h3>
            <p className="text-[#8b9bb4] text-sm leading-relaxed mb-4">Click the Download button below. The file is <code>AEGIS_XII_Setup_v3.exe</code> (~79 MB). Save it anywhere on your system.</p>
            <div className="mt-auto flex items-start gap-2 p-3 rounded-lg bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.05)] text-xs text-[#8b9bb4]">
              <ShieldAlert className="w-4 h-4 text-white shrink-0" />
              <span>Your browser may warn about running .exe files — click <em>Keep</em> or <em>Run anyway</em>.</span>
            </div>
          </div>

          <div className="glass-card p-6 flex flex-col group hover:border-[#a855f7]/30">
            <div className="flex items-center gap-4 mb-4">
              <div className="text-4xl font-bold text-[rgba(255,255,255,0.05)] font-mono">02</div>
              <div className="w-10 h-10 rounded-xl bg-[rgba(168,85,247,0.1)] border border-[rgba(168,85,247,0.2)] flex items-center justify-center text-[#a855f7] shadow-[0_0_15px_rgba(168,85,247,0.2)]">
                <ShieldCheck className="w-5 h-5" />
              </div>
            </div>
            <h3 className="text-xl font-bold mb-3">Accept the UAC Prompt</h3>
            <p className="text-[#8b9bb4] text-sm leading-relaxed mb-4">Windows will display a User Account Control dialog asking for Administrator permission. Click <strong>Yes</strong> to proceed.</p>
            <div className="mt-auto flex items-start gap-2 p-3 rounded-lg bg-[rgba(255,140,0,0.05)] border border-[rgba(255,140,0,0.2)] text-xs text-[#ff8c00]">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>Administrator access is required — raw socket packet capture cannot function without it.</span>
            </div>
          </div>

          <div className="glass-card p-6 flex flex-col group hover:border-[#00e676]/30">
            <div className="flex items-center gap-4 mb-4">
              <div className="text-4xl font-bold text-[rgba(255,255,255,0.05)] font-mono">03</div>
              <div className="w-10 h-10 rounded-xl bg-[rgba(0,230,118,0.1)] border border-[rgba(0,230,118,0.2)] flex items-center justify-center text-[#00e676] shadow-[0_0_15px_rgba(0,230,118,0.2)]">
                <Monitor className="w-5 h-5" />
              </div>
            </div>
            <h3 className="text-xl font-bold mb-3">Run the Setup Wizard</h3>
            <p className="text-[#8b9bb4] text-sm leading-relaxed mb-4">Choose your preferred installation directory and click Install. The process takes under 30 seconds.</p>
            <ul className="mt-auto space-y-2 text-xs text-[#8b9bb4]">
              <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-[#00e676]" /> Start Menu shortcut is created</li>
              <li className="flex items-center gap-2"><span className="w-1 h-1 rounded-full bg-[#00e676]" /> Desktop shortcut is optional</li>
            </ul>
          </div>

          {/* Tips block */}
          <div className="glass-card p-6 md:col-span-2 lg:col-span-3 border-[rgba(168,85,247,0.2)] bg-[rgba(168,85,247,0.02)]">
            <div className="flex items-center gap-3 mb-4">
              <HelpCircle className="w-5 h-5 text-[#a855f7]" />
              <h3 className="text-lg font-bold">Tips & Troubleshooting</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-[#8b9bb4]">
              <div>
                <strong className="text-white">Can't see the tray icon?</strong>
                <p>Click the <code>^</code> chevron in the bottom-right to expand hidden icons. Right-click taskbar → <em>Taskbar settings</em> to pin it permanently.</p>
              </div>
              <div>
                <strong className="text-white">Uninstall</strong>
                <p>Go to <em>Settings → Apps → AEGIS XII → Uninstall</em>. All files and registry entries are cleanly removed.</p>
              </div>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
