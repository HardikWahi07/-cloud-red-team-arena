const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    frame: false,
    transparent: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });

  // In production, this would load the built Next.js app
  win.loadURL('http://localhost:3000');
}

app.whenReady().then(createWindow);

ipcMain.on('execute-command', (event, command) => {
  console.log(`Executing local command with permission: ${command}`);
  // Mock local automation
  event.reply('command-result', `Successfully executed: ${command}`);
});
