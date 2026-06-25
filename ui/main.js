const { app, BrowserWindow, Tray, Menu, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');

let mainWindow;
let tray = null;
let isQuitting = false;
let firewallProcess = null;

// Determine path to firewall executable based on environment (packaged vs dev)
const isPackaged = app.isPackaged;
let firewallExePath;
let dashboardPath;

if (isPackaged) {
  // In production, extraFiles places it in process.resourcesPath/bin
  firewallExePath = path.join(process.resourcesPath, 'bin', 'firewall.exe');
  dashboardPath = path.join(process.resourcesPath, 'dashboard');
} else {
  // In development
  firewallExePath = path.join(__dirname, '..', 'cmake-build-debug', 'firewall.exe');
  dashboardPath = path.join(__dirname, '..', 'dashboard');
  if (!fs.existsSync(firewallExePath)) {
    firewallExePath = path.join(__dirname, '..', 'cmake-build-release', 'firewall.exe');
  }
}

function spawnFirewall() {
  if (!fs.existsSync(firewallExePath)) {
    dialog.showErrorBox('Missing Firewall Core', `Could not find firewall.exe at:\n${firewallExePath}\nPlease build the project first.`);
    app.quit();
    return;
  }

  // Determine working directory (to load config, rules, etc.)
  const cwd = isPackaged ? process.resourcesPath : path.join(__dirname, '..');

  console.log(`Starting firewall.exe from: ${firewallExePath}`);
  
  firewallProcess = spawn(firewallExePath, ['config/rules.conf', 'logs/firewall.log', isPackaged ? 'dashboard/' : 'dashboard/'], {
    cwd: cwd,
    windowsHide: true,
  });

  firewallProcess.stdout.on('data', (data) => {
    console.log(`[FW]: ${data}`);
  });

  firewallProcess.stderr.on('data', (data) => {
    console.error(`[FW ERR]: ${data}`);
  });

  firewallProcess.on('close', (code) => {
    console.log(`firewall.exe exited with code ${code}`);
    if (!isQuitting) {
      dialog.showErrorBox('Firewall Engine Terminated', `The backend engine stopped unexpectedly (Code: ${code}).\nThe UI will now close.`);
      app.quit();
    }
  });
}

function pollBackend(retries, delayMs, callback) {
  const req = http.get('http://127.0.0.1:8080/api/token', (res) => {
    if (res.statusCode === 200) {
      callback(true);
    } else {
      if (retries > 0) setTimeout(() => pollBackend(retries - 1, delayMs, callback), delayMs);
      else callback(false);
    }
  }).on('error', (err) => {
    if (retries > 0) setTimeout(() => pollBackend(retries - 1, delayMs, callback), delayMs);
    else callback(false);
  });
  req.end();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    title: "Aegis XII",
    autoHideMenuBar: true,
    show: false, // hide until loaded
    webPreferences: {
      nodeIntegration: false
    }
  });

  // Wait for the backend to bind to 8080 before loading
  pollBackend(10, 500, (isUp) => {
    if (isUp) {
      mainWindow.loadURL('http://localhost:8080');
      mainWindow.show();
    } else {
      dialog.showErrorBox('Connection Failed', 'Could not connect to the firewall backend on port 8080.');
      app.quit();
    }
  });

  mainWindow.on('close', function (event) {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  const { nativeImage } = require('electron');
  // Load icon if available, otherwise fallback
  const iconPath = path.join(__dirname, 'assets', 'icon.ico');
  if (fs.existsSync(iconPath)) {
    tray = new Tray(iconPath);
  } else {
    tray = new Tray(nativeImage.createEmpty()); 
  }
  
  tray.setToolTip('Aegis XII');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Dashboard',
      click: () => mainWindow.show()
    },
    { type: 'separator' },
    {
      label: 'Quit Aegis',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => mainWindow.show());
}

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (!mainWindow.isVisible()) mainWindow.show();
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    spawnFirewall();
    createWindow();
    createTray();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

app.on('before-quit', () => {
  isQuitting = true;
  if (firewallProcess) {
    firewallProcess.kill();
  }
});
