import { Shield } from 'lucide-react';

export default function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-[rgba(3,5,8,0.85)] border-b border-[rgba(255,255,255,0.05)] backdrop-blur-md transition-all duration-300">
      <div className="max-w-7xl mx-auto px-6 h-[72px] flex items-center justify-between">
        <a href="#home" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#00e5ff] to-[#3b82f6] flex items-center justify-center text-white shadow-[0_0_15px_rgba(0,229,255,0.35)]">
            <Shield className="w-5 h-5" />
          </div>
          <span className="text-xl font-bold tracking-[2px] bg-gradient-to-r from-white to-[#00e5ff] text-transparent bg-clip-text">AEGIS XII</span>
        </a>
        
        <div className="hidden md:flex items-center gap-8">
          <a href="#platform" className="text-sm font-semibold text-[#8b9bb4] hover:text-[#00e5ff] tracking-wide transition-colors">Platform</a>
          <a href="#architecture" className="text-sm font-semibold text-[#8b9bb4] hover:text-[#00e5ff] tracking-wide transition-colors">Architecture</a>
          <a href="#install" className="text-sm font-semibold text-[#8b9bb4] hover:text-[#00e5ff] tracking-wide transition-colors">Install Guide</a>
          <a href="#download" className="px-5 py-2.5 rounded-full bg-[rgba(0,229,255,0.1)] border border-[rgba(0,229,255,0.3)] text-[#00e5ff] text-sm font-bold uppercase tracking-wide hover:bg-[#00e5ff] hover:text-black hover:shadow-[0_0_20px_rgba(0,229,255,0.4)] transition-all">
            Download v3.0
          </a>
        </div>
      </div>
    </nav>
  );
}
