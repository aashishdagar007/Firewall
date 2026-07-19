import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-[rgba(255,255,255,0.05)] bg-[rgba(3,5,8,0.9)] py-8 relative z-10">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2 opacity-50 hover:opacity-100 transition-opacity">
          <Shield className="w-5 h-5 text-white" />
          <span className="text-sm font-bold tracking-[2px] text-white">AEGIS XII</span>
        </div>
        <p className="text-xs text-[#8b9bb4]">&copy; {new Date().getFullYear()} ASD Solutions · Enterprise Security Division</p>
      </div>
    </footer>
  );
}
