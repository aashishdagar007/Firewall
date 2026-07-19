import { useEffect, useState } from 'react';
import { initParticlesEngine } from '@tsparticles/react';
import { loadFull } from 'tsparticles';
import ParticlesBackground from './components/ParticlesBackground';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import MetricCards from './components/MetricCards';
import LiveFeed from './components/LiveFeed';

function App() {
  const [init, setInit] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadFull(engine);
    }).then(() => {
      setInit(true);
    });
  }, []);

  return (
    <div className="flex h-screen bg-[#030508] text-[#e2e8f0] font-sans overflow-hidden">
      {init && <ParticlesBackground />}
      
      {/* Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative z-10">
        <Header />

        <section className="flex-1 p-6 overflow-y-auto flex flex-col gap-4">
          {activeTab === 'dashboard' && (
            <>
              <MetricCards />
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-1 min-h-0">
                <LiveFeed />
                {/* Space for future components (e.g. charts) */}
                <div className="glass-card flex flex-col">
                  <div className="uppercase tracking-widest text-xs font-semibold text-[#8b9bb4] mb-4">System Anomaly Monitor</div>
                  <div className="flex-1 flex items-center justify-center text-sm text-[#8b9bb4]">
                    Anomaly chart placeholder
                  </div>
                </div>
              </div>
            </>
          )}
          {activeTab !== 'dashboard' && (
            <div className="glass-card flex-1 flex items-center justify-center">
              <div className="text-xl tracking-widest text-[#8b9bb4] uppercase">{activeTab} View Placeholder</div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
