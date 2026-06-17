document.addEventListener('DOMContentLoaded', () => {

    // ── Navbar scroll shadow ──────────────────────────────────
    const navbar = document.getElementById('navbar');
    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });

    // ── Mobile menu toggle ───────────────────────────────────
    const mobileBtn    = document.getElementById('mobileMenuBtn');
    const mobileDrawer = document.getElementById('mobileDrawer');
    if (mobileBtn && mobileDrawer) {
        mobileBtn.addEventListener('click', () => {
            mobileDrawer.classList.toggle('open');
        });
        // Close drawer when a link is clicked
        mobileDrawer.querySelectorAll('a').forEach(a => {
            a.addEventListener('click', () => mobileDrawer.classList.remove('open'));
        });
    }

    // ── Scroll reveal ─────────────────────────────────────────
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { rootMargin: '0px 0px -60px 0px', threshold: 0.05 });

    document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

    // ── Live terminal stats (mock fluctuation / real API) ────
    const heroPkts    = document.getElementById('heroPkts');
    const heroThreats = document.getElementById('heroThreats');
    const heroProcs   = document.getElementById('heroProcs');

    let pktBase = 48291;
    let threats = 0;
    let procs   = 12;

    // Try to pull real stats from the running firewall
    async function fetchStats() {
        try {
            const token = sessionStorage.getItem('fw_api_token');
            const headers = token ? { Authorization: `Bearer ${token}` } : {};
            const res = await fetch('/api/stats', { headers });
            if (res.ok) {
                const d = await res.json();
                if (heroPkts)    heroPkts.textContent    = Number(d.total).toLocaleString();
                if (heroThreats) heroThreats.textContent = Number(d.blocked).toLocaleString();
                return;
            }
        } catch (_) { /* fall through to mock */ }

        // Mock fluctuation for demo / standalone website view
        const delta  = Math.floor(Math.random() * 3200) - 800;
        pktBase = Math.max(0, pktBase + delta);
        if (Math.random() > 0.85) threats += Math.floor(Math.random() * 3);
        if (Math.random() > 0.9)  procs   = 10 + Math.floor(Math.random() * 8);
        if (heroPkts)    heroPkts.textContent    = pktBase.toLocaleString();
        if (heroThreats) heroThreats.textContent = threats.toString();
        if (heroProcs)   heroProcs.textContent   = procs.toString();
    }

    fetchStats();
    setInterval(fetchStats, 1800);

    // ── Smooth anchor scrolling (offset for fixed nav) ───────
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', e => {
            const target = document.querySelector(anchor.getAttribute('href'));
            if (!target) return;
            e.preventDefault();
            const top = target.getBoundingClientRect().top + window.scrollY - 72;
            window.scrollTo({ top, behavior: 'smooth' });
        });
    });

});
