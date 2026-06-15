document.addEventListener('DOMContentLoaded', () => {
    
    // Smooth scrolling and HUD active state update
    const sections = document.querySelectorAll('.section-step');
    const hudLinks = document.querySelectorAll('.hud-link');

    const observerOptions = {
        root: null,
        rootMargin: '-20% 0px -70% 0px', // Trigger when section is in top part of viewport
        threshold: 0
    };

    const sectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Remove active class from all
                hudLinks.forEach(link => link.classList.remove('active'));
                
                // Add active class to corresponding link
                const activeId = entry.target.getAttribute('id');
                const activeLink = document.querySelector(`.hud-link[href="#${activeId}"]`);
                if (activeLink) {
                    activeLink.classList.add('active');
                }
            }
        });
    }, observerOptions);

    sections.forEach(sec => sectionObserver.observe(sec));

    // Reveal elements on scroll
    const revealOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const revealObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                observer.unobserve(entry.target);
            }
        });
    }, revealOptions);

    // Apply reveal to cards and sections
    const revealElements = document.querySelectorAll('.card, .split-content, .split-visual, .cta-container, .hero-content, .hero-visual');
    
    revealElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.8s ease-out, transform 0.8s ease-out';
        revealObserver.observe(el);
    });

    // Simulate real-time packet scanning in the mock UI
    const packetCounter = document.querySelector('.pulse-text');
    if (packetCounter) {
        setInterval(() => {
            const current = parseInt(packetCounter.textContent.replace(/,/g, '').split(' ')[0]) || 1492304;
            // Random fluctuation to look realistic
            const fluctuation = Math.floor(Math.random() * 8000) - 2000; 
            const nextVal = current + fluctuation;
            packetCounter.textContent = nextVal.toLocaleString() + ' /s';
        }, 1200);
    }
    
    // Status text random glitch effect for "SECURE"
    const statusText = document.querySelector('.status-text');
    if (statusText) {
        setInterval(() => {
            if (Math.random() > 0.95) {
                const originalText = statusText.innerText;
                statusText.innerText = "SCNNNG";
                setTimeout(() => {
                    statusText.innerText = originalText;
                }, 150);
            }
        }, 2000);
    }
});
