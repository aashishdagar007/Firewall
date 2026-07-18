const { app, BrowserWindow, Tray, Menu, dialog, nativeImage, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');

// ── Single instance lock ────────────────────────────────────────────────────
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

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
      const rel  = path.join(__dirname, '..', 'cmake-build-release', 'firewall.exe');
      const dbg  = path.join(__dirname, '..', 'cmake-build-debug',   'firewall.exe');
      return fs.existsSync(rel) ? rel : dbg;
    })();

const websitePath   = isPackaged
  ? path.join(process.resourcesPath, 'website', 'index.html')
  : path.join(__dirname, '..', 'Website', 'index.html');

const dashboardRoot = isPackaged
  ? path.join(process.resourcesPath, 'dashboard')
  : path.join(__dirname, '..', 'dashboard');

const configPath = isPackaged
  ? path.join(process.resourcesPath, 'config', 'rules.conf')
  : path.join(__dirname, '..', 'config', 'rules.conf');

const logsDir = isPackaged
  ? path.join(process.resourcesPath, 'logs')
  : path.join(__dirname, '..', 'logs');

const logFile = path.join(logsDir, 'firewall.log');

const iconPath = path.join(__dirname, 'assets', 'icon.ico');

// ── Ensure logs directory exists ────────────────────────────────────────────
function ensureLogsDir() {
  try {
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
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

  firewallProcess.stdout.on('data', (data) => {
    console.log(`[FW]: ${data.toString().trim()}`);
  });

  firewallProcess.stderr.on('data', (data) => {
    console.error(`[FW ERR]: ${data.toString().trim()}`);
  });

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

// ── Poll backend until ready ────────────────────────────────────────────────
function pollBackend(retries, delayMs, callback) {
  http.get('http://127.0.0.1:8080/api/token', (res) => {
    if (res.statusCode === 200) {
      callback(true);
    } else {
      if (retries > 0) setTimeout(() => pollBackend(retries - 1, delayMs, callback), delayMs);
      else callback(false);
    }
  }).on('error', () => {
    if (retries > 0) setTimeout(() => pollBackend(retries - 1, delayMs, callback), delayMs);
    else callback(false);
  }).end();
}

// ── Create main window ──────────────────────────────────────────────────────
function createWindow() {
  const icon = fs.existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createEmpty();

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    title: 'AEGIS XII',
    icon: icon,
    autoHideMenuBar: true,
    show: false,
    backgroundColor: '#030509',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false,   // allows loadFile to load local CSS/JS/fonts
    }
  });

  // Load the marketing website as the home page
  mainWindow.loadFile(websitePath);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Clicking close hides the window — app lives in the tray
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

// ── Create system tray icon ─────────────────────────────────────────────────
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
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        } else {
          createWindow();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Terminate AEGIS XII',
      click: () => {
        isQuitting = true;
        if (firewallProcess) {
          try { firewallProcess.kill(); } catch (e) { /* already dead */ }
        }
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);

  // Double-click tray icon → show window
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    } else {
      createWindow();
    }
  });
}

// ── Auto-start on Windows login ─────────────────────────────────────────────
function configureAutoStart() {
  if (isPackaged) {
    app.setLoginItemSettings({
      openAtLogin: true,
      openAsHidden: true,  // start minimised to tray, no window popup
    });
  }
}

// ── App lifecycle ───────────────────────────────────────────────────────────
app.on('second-instance', () => {
  // Someone tried to launch a second instance — focus existing window
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

// Prevent the app from quitting when all windows are closed (live in tray)
app.on('window-all-closed', (e) => {
  if (!isQuitting) e.preventDefault();
});

app.on('before-quit', () => {
  isQuitting = true;
  if (firewallProcess) {
    try { firewallProcess.kill(); } catch (e) { /* already dead */ }
  }
});
