document.addEventListener('DOMContentLoaded', () => {
    // Scroll Reveal Animation
    const revealElements = document.querySelectorAll('.reveal');
    
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    });

    revealElements.forEach(el => revealObserver.observe(el));

    // Navbar Scroll Effect
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 20) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Terminal Simulator Logic
    const termPkts = document.getElementById('term-pkts');
    const termThreats = document.getElementById('term-threats');
    
    if (termPkts && termThreats) {
        let pkts = 84920;
        let threats = 42;

        setInterval(() => {
            // Randomly increase packets
            pkts += Math.floor(Math.random() * 500) + 100;
            termPkts.textContent = pkts.toLocaleString();
            
            // Occasionally find a threat
            if (Math.random() > 0.8) {
                threats += 1;
                termThreats.textContent = threats.toLocaleString();
                
                // Add alert class temporarily
                termThreats.classList.add('alert');
                setTimeout(() => termThreats.classList.remove('alert'), 500);
            }
        }, 1000);
    }
});
