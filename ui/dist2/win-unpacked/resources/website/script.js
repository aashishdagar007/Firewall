/* ═══════════════════════════════════════════════════
   AEGIS XII — Enhanced Interactive Script
   ═══════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    /* ═══════════════════════════════════════════════════
       0. ELECTRON DETECTION
       When running inside the installed Electron app, the
       user agent contains "Electron". In that case the app
       is ALREADY installed — downloading the installer
       again makes no sense. We swap every download button
       to an "Already Running" state and add an
       "Open Dashboard" action instead.
    ═══════════════════════════════════════════════════ */
    const isElectron = /electron/i.test(navigator.userAgent);

    if (isElectron) {
        // ── Mark <body> so CSS can also react ──
        document.body.classList.add('is-electron');

        // ── Swap every download / deploy button ──
        const downloadSelectors = [
            '#btn-deploy',          // hero "Deploy AEGIS XII"
            '.btn-download',        // CTA "Download v3.0 Installer"
            '[download]',           // any element with a download attribute
        ];

        downloadSelectors.forEach(sel => {
            document.querySelectorAll(sel).forEach(el => {
                // Remove download behaviour
                el.removeAttribute('href');
                el.removeAttribute('download');

                // Style as "already installed"
                el.classList.add('btn-installed');
                el.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                         stroke="currentColor" stroke-width="2.5"
                         stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                    AEGIS XII is Running
                `;
                el.style.cursor = 'default';
                el.style.pointerEvents = 'none';
            });
        });

        // ── Inject "Open Dashboard" button next to hero deploy btn ──
        const heroBtns = document.querySelector('.hero-btns');
        if (heroBtns) {
            const dashBtn = document.createElement('a');
            dashBtn.href = 'http://localhost:8080';
            dashBtn.className = 'btn-ghost btn-dashboard';
            dashBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2.2"
                     stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2"/>
                    <line x1="3" y1="9" x2="21" y2="9"/>
                    <line x1="9" y1="21" x2="9" y2="9"/>
                </svg>
                Open Dashboard
            `;
            heroBtns.appendChild(dashBtn);
        }

        // ── Show a status banner at top of page ──
        const banner = document.createElement('div');
        banner.id = 'electron-banner';
        banner.innerHTML = `
            <div class="eb-inner">
                <span class="eb-dot"></span>
                <strong>AEGIS XII is active</strong> — Running on this device.
                <a href="http://localhost:8080" class="eb-link">Open live dashboard →</a>
            </div>
        `;
        document.body.prepend(banner);

        // ── Inject banner + installed-button styles ──
        const style = document.createElement('style');
        style.textContent = `
            /* Status banner */
            #electron-banner {
                position: fixed;
                top: 0; left: 0; right: 0;
                z-index: 2000;
                background: linear-gradient(90deg, #059669 0%, #0ea5e9 100%);
                padding: 0;
                display: flex;
                justify-content: center;
            }
            .eb-inner {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 8px 24px;
                font-size: 0.82rem;
                font-weight: 500;
                color: white;
                flex-wrap: wrap;
                justify-content: center;
            }
            .eb-dot {
                display: inline-block;
                width: 7px; height: 7px;
                background: #fff;
                border-radius: 50%;
                animation: eb-blink 2s ease-in-out infinite;
                flex-shrink: 0;
            }
            @keyframes eb-blink {
                0%, 100% { opacity: 1; }
                50%       { opacity: 0.35; }
            }
            .eb-link {
                color: rgba(255,255,255,0.88);
                text-decoration: underline;
                text-underline-offset: 3px;
                transition: color 0.2s;
            }
            .eb-link:hover { color: #fff; }

            /* Push page content below the banner */
            body.is-electron .navbar { top: calc(16px + 36px); }
            body.is-electron .hero   { padding-top: calc(160px + 36px); }

            /* "Already Running" button style */
            .btn-installed {
                background: linear-gradient(135deg, #059669 0%, #0ea5e9 100%) !important;
                box-shadow: 0 8px 24px rgba(5,150,105,0.25) !important;
                opacity: 0.9;
                gap: 8px;
            }
            .btn-installed:hover {
                transform: none !important;
                box-shadow: 0 8px 24px rgba(5,150,105,0.25) !important;
            }

            /* Dashboard shortcut button */
            .btn-dashboard {
                border-color: rgba(14,165,233,0.3) !important;
            }
        `;
        document.head.appendChild(style);
    }

    /* ── 1. Scroll Reveal ─────────────────────────────── */
    const revealEls = document.querySelectorAll('.reveal');
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    revealEls.forEach(el => revealObserver.observe(el));

    /* ── 2. Navbar scroll effect ──────────────────────── */
    const navbar = document.getElementById('navbar');
    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });

    /* ── 3. Feature card mouse-glow tracking ──────────── */
    document.querySelectorAll('.feat-card').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--mx', `${((e.clientX - rect.left) / rect.width) * 100}%`);
            card.style.setProperty('--my', `${((e.clientY - rect.top) / rect.height) * 100}%`);
        });
    });

    /* ── 4. Animated stat counters ────────────────────── */
    const statNums = document.querySelectorAll('.stat-num[data-target]');
    const countObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;
            const el = entry.target;
            const target = parseInt(el.dataset.target, 10);
            const start = performance.now();
            const animate = (now) => {
                const progress = Math.min((now - start) / 1400, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                el.textContent = Math.round(eased * target);
                if (progress < 1) requestAnimationFrame(animate);
                else el.textContent = target;
            };
            requestAnimationFrame(animate);
            countObserver.unobserve(el);
        });
    }, { threshold: 0.5 });
    statNums.forEach(el => countObserver.observe(el));

    /* ── 5. Smooth active nav link on scroll ──────────── */
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link');
    const sectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                navLinks.forEach(link => {
                    const active = link.getAttribute('href') === `#${entry.target.id}`;
                    link.style.color = active ? 'var(--blue-2)' : '';
                    link.style.background = active ? 'var(--blue-glow)' : '';
                });
            }
        });
    }, { threshold: 0.4 });
    sections.forEach(s => sectionObserver.observe(s));

    /* ── 6. Parallax orbs on mouse move ───────────────── */
    const orbs = document.querySelectorAll('.orb');
    document.addEventListener('mousemove', (e) => {
        const dx = (e.clientX - window.innerWidth  / 2) / window.innerWidth;
        const dy = (e.clientY - window.innerHeight / 2) / window.innerHeight;
        orbs.forEach((orb, i) => {
            orb.style.transform = `translate(${dx * (i+1) * 10}px, ${dy * (i+1) * 10}px)`;
        });
    }, { passive: true });

    /* ── 7. CTA button ripple effect ──────────────────── */
    document.querySelectorAll('.btn-primary:not(.btn-installed), .btn-ghost').forEach(btn => {
        btn.addEventListener('click', function (e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height) * 2;
            ripple.style.cssText = `
                position:absolute; border-radius:50%;
                width:${size}px; height:${size}px;
                left:${e.clientX - rect.left - size/2}px;
                top:${e.clientY - rect.top - size/2}px;
                background:rgba(255,255,255,0.3);
                transform:scale(0); animation:ripple-anim 0.6s ease-out;
                pointer-events:none;
            `;
            if (getComputedStyle(this).position === 'static') this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            setTimeout(() => ripple.remove(), 650);
        });
    });

    if (!document.getElementById('ripple-style')) {
        const s = document.createElement('style');
        s.id = 'ripple-style';
        s.textContent = `@keyframes ripple-anim { to { transform: scale(1); opacity: 0; } }`;
        document.head.appendChild(s);
    }

    /* ── 8. Hero shield tilt on mouse ─────────────────── */
    const shieldWrap = document.querySelector('.shield-wrap');
    if (shieldWrap) {
        const heroSection = document.querySelector('.hero');
        heroSection.addEventListener('mousemove', (e) => {
            const rect = shieldWrap.getBoundingClientRect();
            const rx = ((e.clientY - rect.top  - rect.height/2) / window.innerHeight) * 12;
            const ry = ((e.clientX - rect.left - rect.width /2) / window.innerWidth ) * -12;
            shieldWrap.style.transform = `perspective(600px) rotateX(${rx}deg) rotateY(${ry}deg)`;
        });
        heroSection.addEventListener('mouseleave', () => {
            shieldWrap.style.transition = 'transform 0.6s ease';
            shieldWrap.style.transform  = 'perspective(600px) rotateX(0) rotateY(0)';
        });
        heroSection.addEventListener('mouseenter', () => {
            shieldWrap.style.transition = 'transform 0.1s ease';
        });
    }

});
