
import Particles from '@tsparticles/react';

const ParticlesBackground = () => {
  return (
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
      className="fixed inset-0 -z-10 pointer-events-none"
    />
  );
};

export default ParticlesBackground;
