/* ═══════════════════════════════════════════════════
   AEGIS XII — Enhanced Interactive Script
   ═══════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

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
    let lastY = 0;
    window.addEventListener('scroll', () => {
        const y = window.scrollY;
        if (y > 40) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
        lastY = y;
    }, { passive: true });

    /* ── 3. Feature card mouse-glow tracking ──────────── */
    document.querySelectorAll('.feat-card').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            card.style.setProperty('--mx', `${x}%`);
            card.style.setProperty('--my', `${y}%`);
        });
    });

    /* ── 4. Animated stat counters ────────────────────── */
    const statNums = document.querySelectorAll('.stat-num[data-target]');
    const countObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;
            const el = entry.target;
            const target = parseInt(el.dataset.target, 10);
            const duration = 1400;
            const start = performance.now();
            const animate = (now) => {
                const elapsed = now - start;
                const progress = Math.min(elapsed / duration, 1);
                // Ease out cubic
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
    const sections = document.querySelectorAll('section[id], div[id]');
    const navLinks = document.querySelectorAll('.nav-link');
    const sectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                navLinks.forEach(link => {
                    link.style.color = '';
                    link.style.background = '';
                    if (link.getAttribute('href') === `#${entry.target.id}`) {
                        link.style.color = 'var(--blue-2)';
                        link.style.background = 'var(--blue-glow)';
                    }
                });
            }
        });
    }, { threshold: 0.4 });
    sections.forEach(s => sectionObserver.observe(s));

    /* ── 6. Parallax orbs on mouse move ───────────────── */
    const orbs = document.querySelectorAll('.orb');
    document.addEventListener('mousemove', (e) => {
        const cx = window.innerWidth / 2;
        const cy = window.innerHeight / 2;
        const dx = (e.clientX - cx) / cx;
        const dy = (e.clientY - cy) / cy;
        orbs.forEach((orb, i) => {
            const factor = (i + 1) * 10;
            orb.style.transform = `translate(${dx * factor}px, ${dy * factor}px)`;
        });
    }, { passive: true });

    /* ── 7. CTA button ripple effect ──────────────────── */
    document.querySelectorAll('.btn-primary, .btn-ghost').forEach(btn => {
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
            if (!getComputedStyle(this).position || getComputedStyle(this).position === 'static') {
                this.style.position = 'relative';
            }
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            setTimeout(() => ripple.remove(), 650);
        });
    });

    /* Inject ripple keyframe once */
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
            const cx = rect.left + rect.width / 2;
            const cy = rect.top + rect.height / 2;
            const rx = ((e.clientY - cy) / window.innerHeight) * 12;
            const ry = ((e.clientX - cx) / window.innerWidth) * -12;
            shieldWrap.style.transform = `perspective(600px) rotateX(${rx}deg) rotateY(${ry}deg)`;
        });
        heroSection.addEventListener('mouseleave', () => {
            shieldWrap.style.transform = 'perspective(600px) rotateX(0) rotateY(0)';
            shieldWrap.style.transition = 'transform 0.6s ease';
        });
        heroSection.addEventListener('mouseenter', () => {
            shieldWrap.style.transition = 'transform 0.1s ease';
        });
    }

});
