const { app, BrowserWindow, Tray, Menu, dialog, nativeImage } = require('electron');
const path   = require('path');
const { spawn } = require('child_process');
const fs     = require('fs');
const http   = require('http');

// ── Single instance lock ────────────────────────────────────────────────────
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) { app.quit(); process.exit(0); }

// ── State ───────────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;
let firewallProcess = null;
let firewallRestartCount = 0;
const MAX_FIREWALL_RESTARTS = 3;

// ── Paths (packaged vs dev) ─────────────────────────────────────────────────
const isPackaged = app.isPackaged;

const firewallExePath = isPackaged
  ? path.join(process.resourcesPath, 'bin', 'firewall.exe')
  : (() => {
      const rel = path.join(__dirname, '..', 'cmake-build-release', 'firewall.exe');
      const dbg = path.join(__dirname, '..', 'cmake-build-debug',   'firewall.exe');
      return fs.existsSync(rel) ? rel : dbg;
    })();

const dashboardRoot = isPackaged
  ? path.join(process.resourcesPath, 'dashboard')
  : path.join(__dirname, '..', 'dashboard');

const configPath = isPackaged
  ? path.join(process.resourcesPath, 'config', 'rules.conf')
  : path.join(__dirname, '..', 'config', 'rules.conf');

const logsDir = isPackaged
  ? path.join(process.resourcesPath, 'logs')
  : path.join(__dirname, '..', 'logs');

const logFile  = path.join(logsDir, 'firewall.log');
const iconPath = path.join(__dirname, 'assets', 'icon.ico');

// Dashboard URL served by firewall.exe
const DASHBOARD_URL = 'http://127.0.0.1:8080';

// ── Ensure logs directory exists ────────────────────────────────────────────
function ensureLogsDir() {
  try {
    if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
  } catch (e) {
    console.error('Could not create logs directory:', e);
  }
}

// ── Spawn firewall.exe (with restart-on-crash) ──────────────────────────────
function spawnFirewall() {
  if (!fs.existsSync(firewallExePath)) {
    dialog.showErrorBox(
      'AEGIS XII — Missing Engine',
      `Could not find firewall.exe at:\n${firewallExePath}\n\nPlease reinstall AEGIS XII.`
    );
    app.quit();
    return;
  }

  const cwd = isPackaged ? process.resourcesPath : path.join(__dirname, '..');
  console.log(`[AEGIS] Starting firewall engine: ${firewallExePath}`);

  firewallProcess = spawn(
    firewallExePath,
    [configPath, logFile, dashboardRoot + path.sep],
    { cwd, windowsHide: true }
  );

  firewallProcess.stdout.on('data', d => console.log(`[FW]: ${d.toString().trim()}`));
  firewallProcess.stderr.on('data', d => console.error(`[FW ERR]: ${d.toString().trim()}`));

  firewallProcess.on('close', (code) => {
    console.log(`[AEGIS] firewall.exe exited with code ${code}`);
    if (!isQuitting) {
      if (firewallRestartCount < MAX_FIREWALL_RESTARTS) {
        firewallRestartCount++;
        console.log(`[AEGIS] Restarting firewall engine (attempt ${firewallRestartCount}/${MAX_FIREWALL_RESTARTS})...`);
        setTimeout(spawnFirewall, 2000);
      } else {
        dialog.showErrorBox(
          'AEGIS XII — Engine Failure',
          `The firewall engine stopped unexpectedly (exit code: ${code}) and could not be restarted.\n\nThe application will now close.`
        );
        app.quit();
      }
    }
  });
}

// ── Poll backend until the dashboard is ready ───────────────────────────────
function pollBackend(retries, delayMs, callback) {
  http.get(`${DASHBOARD_URL}/api/token`, (res) => {
    // Any response (even 403) means the server is up
    callback(true);
  }).on('error', () => {
    if (retries > 0) setTimeout(() => pollBackend(retries - 1, delayMs, callback), delayMs);
    else callback(false);
  }).end();
}

// ── Create main window — loads the live dashboard directly ──────────────────
function createWindow() {
  const icon = fs.existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createEmpty();

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 600,
    title: 'AEGIS XII',
    icon,
    autoHideMenuBar: true,
    show: false,
    backgroundColor: '#0b1020',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    }
  });

  // Show a "connecting" splash while the firewall boots
  mainWindow.loadURL('data:text/html,<body style="background:#0b1020;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui"><div style="text-align:center;color:#fff"><svg width=60 height=60 viewBox="0 0 24 24" fill="none" stroke="#0ea5e9" stroke-width="1.5" style="margin-bottom:16px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg><br><span style="font-size:1.1rem;font-weight:600;letter-spacing:-.01em">AEGIS XII</span><br><span style="font-size:.85rem;color:#7a8fa6;margin-top:6px;display:block">Starting firewall engine&hellip;</span></div></body>');

  mainWindow.once('ready-to-show', () => mainWindow.show());

  // Close → hide to tray
  mainWindow.on('close', (event) => {
    if (!isQuitting) { event.preventDefault(); mainWindow.hide(); }
  });

  // Once the window is shown, poll until the dashboard is ready, then navigate
  mainWindow.once('show', () => {
    pollBackend(60, 1000, (ready) => {
      if (ready) {
        mainWindow.loadURL(DASHBOARD_URL);
      } else {
        // Dashboard didn't come up — show error page
        mainWindow.loadURL(
          'data:text/html,<body style="background:#0b1020;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui"><div style="text-align:center;color:#ef4444;max-width:400px"><svg width=48 height=48 viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom:12px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1=12 y1=9 x2=12 y2=13/><line x1=12 y1=17 x2=12.01 y2=17/></svg><br><b>Engine Failed to Start</b><br><span style="color:#7a8fa6;font-size:.85rem;margin-top:6px;display:block">The firewall engine did not respond. Please re-launch AEGIS XII as Administrator.</span></div></body>'
        );
      }
    });
  });
}

// ── System tray ─────────────────────────────────────────────────────────────
function createTray() {
  const icon = fs.existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createEmpty();

  tray = new Tray(icon);
  tray.setToolTip('AEGIS XII — Active');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Dashboard',
      click: () => {
        if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
        else createWindow();
      }
    },
    { type: 'separator' },
    {
      label: 'Terminate AEGIS XII',
      click: () => {
        isQuitting = true;
        if (firewallProcess) { try { firewallProcess.kill(); } catch (e) {} }
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
    else createWindow();
  });
}

// ── Auto-start on Windows login ─────────────────────────────────────────────
function configureAutoStart() {
  if (isPackaged) {
    app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true });
  }
}

// ── App lifecycle ───────────────────────────────────────────────────────────
app.on('second-instance', () => {
  if (mainWindow) {
    if (!mainWindow.isVisible()) mainWindow.show();
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

app.whenReady().then(() => {
  ensureLogsDir();
  spawnFirewall();
  createWindow();
  createTray();
  configureAutoStart();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', (e) => { if (!isQuitting) e.preventDefault(); });

app.on('before-quit', () => {
  isQuitting = true;
  if (firewallProcess) { try { firewallProcess.kill(); } catch (e) {} }
});
