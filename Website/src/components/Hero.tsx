import { useEffect, useState } from 'react';
import { Download, ChevronRight, Shield } from 'lucide-react';
import Particles, { initParticlesEngine } from '@tsparticles/react';
import { loadFull } from 'tsparticles';

export default function Hero() {
  const [init, setInit] = useState(false);

  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadFull(engine);
    }).then(() => {
      setInit(true);
    });
  }, []);

  return (
    <section id="home" className="relative min-h-[90vh] flex items-center pt-20 overflow-hidden">
      {/* Background Particles replacing old orbs */}
      {init && (
        <Particles
          id="tsparticles"
          options={{
            background: { color: { value: 'transparent' } },
            fpsLimit: 60,
            interactivity: {
              events: { onHover: { enable: true, mode: 'repulse' } },
              modes: { repulse: { distance: 100, duration: 0.4 } },
            },
            particles: {
              color: { value: ['#00e5ff', '#3b82f6', '#a855f7'] },
              links: { color: '#ffffff', distance: 150, enable: true, opacity: 0.1, width: 1 },
              move: { enable: true, speed: 1 },
              number: { value: 60 },
              opacity: { value: 0.3 },
              size: { value: { min: 1, max: 3 } },
            },
            detectRetina: true,
          }}
          className="absolute inset-0 -z-10 opacity-60"
        />
      )}

      {/* Grid overlay */}
      <div className="absolute inset-0 -z-10 bg-[linear-gradient(to_right,rgba(255,255,255,0.015)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.015)_1px,transparent_1px)] bg-[length:44px_44px]" />

      <div className="max-w-7xl mx-auto px-6 w-full grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
        
        {/* Left Content */}
        <div className="flex flex-col items-start gap-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[rgba(0,229,255,0.3)] bg-[rgba(0,229,255,0.05)] shadow-[0_0_15px_rgba(0,229,255,0.15)] animate-fade-in">
            <span className="w-2 h-2 rounded-full bg-[#00e5ff] shadow-[0_0_8px_#00e5ff] animate-pulse" />
            <span className="text-[#00e5ff] text-xs font-bold tracking-wider uppercase">Version 3.0 — Now Available</span>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold leading-tight animate-fade-in-up" style={{animationDelay: '100ms'}}>
            Network Security<br />
            <span className="bg-gradient-to-r from-[#00e5ff] to-[#3b82f6] text-transparent bg-clip-text">Reimagined.</span>
          </h1>

          <p className="text-lg text-[#8b9bb4] max-w-xl leading-relaxed animate-fade-in-up" style={{animationDelay: '200ms'}}>
            A native, real-time packet inspection engine built for Windows. Protect your local network with intelligent rules, DNS filtering, and autonomous threat banning.
          </p>

          <div className="flex flex-wrap items-center gap-4 mt-4 animate-fade-in-up" style={{animationDelay: '300ms'}}>
            <a href="#download" className="flex items-center gap-2 px-8 py-4 rounded-xl bg-gradient-to-r from-[#00e5ff] to-[#3b82f6] text-white font-bold text-sm tracking-wide shadow-[0_0_20px_rgba(0,229,255,0.4)] hover:shadow-[0_0_30px_rgba(0,229,255,0.6)] hover:-translate-y-0.5 transition-all">
              <Download className="w-5 h-5" />
              Deploy AEGIS XII
            </a>
            <a href="#platform" className="flex items-center gap-2 px-8 py-4 rounded-xl text-[#e2e8f0] font-semibold text-sm tracking-wide border border-[rgba(255,255,255,0.1)] hover:bg-[rgba(255,255,255,0.05)] hover:border-[rgba(255,255,255,0.2)] transition-all">
              Explore Platform
              <ChevronRight className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Right Graphic */}
        <div className="relative flex justify-center items-center h-[500px] animate-fade-in" style={{animationDelay: '200ms'}}>
          <div className="relative w-64 h-64 flex items-center justify-center">
            {/* Animated Rings */}
            <div className="absolute inset-0 border border-[rgba(0,229,255,0.2)] rounded-full animate-[spin_10s_linear_infinite]" />
            <div className="absolute -inset-8 border border-[rgba(59,130,246,0.15)] border-dashed rounded-full animate-[spin_15s_linear_infinite_reverse]" />
            <div className="absolute -inset-16 border border-[rgba(168,85,247,0.1)] rounded-full animate-[spin_20s_linear_infinite]" />
            
            {/* Core Shield */}
            <div className="relative w-32 h-32 rounded-2xl bg-gradient-to-br from-[rgba(0,229,255,0.1)] to-[rgba(59,130,246,0.1)] border border-[#00e5ff] flex items-center justify-center backdrop-blur-md shadow-[0_0_40px_rgba(0,229,255,0.3)]">
              <Shield className="w-16 h-16 text-[#00e5ff] drop-shadow-[0_0_15px_rgba(0,229,255,0.8)]" />
            </div>

            {/* Orbiting Dots */}
            <div className="absolute w-full h-full animate-[spin_8s_linear_infinite]">
              <div className="absolute -top-1.5 left-1/2 w-3 h-3 bg-[#00e5ff] rounded-full shadow-[0_0_10px_#00e5ff]" />
            </div>
            <div className="absolute -inset-8 animate-[spin_12s_linear_infinite_reverse]">
              <div className="absolute bottom-4 left-4 w-2 h-2 bg-[#a855f7] rounded-full shadow-[0_0_10px_#a855f7]" />
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}
