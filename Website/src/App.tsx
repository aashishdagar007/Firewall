
import { useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import StatsBar from './components/StatsBar';
import PlatformFeatures from './components/PlatformFeatures';
import Architecture from './components/Architecture';
import InstallGuide from './components/InstallGuide';
import DownloadCTA from './components/DownloadCTA';
import Footer from './components/Footer';
import LegalCenter, { type LegalDocument } from './components/LegalCenter';
import CookieConsent from './components/CookieConsent';

function App() {
  const [legalDocument, setLegalDocument] = useState<LegalDocument | null>(null);
  return (
    <div className="bg-[#030508] min-h-screen text-[#e2e8f0] font-sans selection:bg-[#00e5ff]/30 selection:text-white">
      <Navbar />
      <Hero />
      <StatsBar />
      <PlatformFeatures />
      <Architecture />
      <InstallGuide />
      <DownloadCTA onOpenPolicy={setLegalDocument} />
      <Footer onOpenPolicy={setLegalDocument} />
      <CookieConsent onOpenPolicy={() => setLegalDocument('cookies')} />
      <LegalCenter document={legalDocument} onClose={() => setLegalDocument(null)} />
    </div>
  );
}

export default App;
