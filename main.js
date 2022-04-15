// Modules to control application life and create native browser window
const {app, BrowserWindow, ipcMain, remote} = require('electron')
const path = require('path')

let middlewareHost;
let once = false;

function once_f(txt) {
    if (once == false) {
        once = true;
        middlewareHost = txt.replace(/(\r\n|\n|\r)/gm, "");;
        app.whenReady().then(() => {
            createWindow()

            app.on('activate', function () {
                // On macOS it's common to re-create a window in the app when the
                // dock icon is clicked and there are no other windows open.
                if (BrowserWindow.getAllWindows().length === 0) createWindow()
            })
        })
    }
}

// starting python server
var python = require('child_process').spawn('./venv/Scripts/python.exe', ['./client.py']);
python.stdout.on('data', function (data) {
    let txt = data.toString('utf8');
    console.log("Middleware: ", txt);
    if (txt.includes("http://") && once == false) {
        once_f(txt);
    }
});


function createWindow() {
    // Create the browser window.
    const mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js')
        }
    })

    // and load the index.html of the app.
    mainWindow.loadFile('index.html')


    // python.stderr.on('data', (data) => {
    //   console.log(`stderr: ${data}`); // when error
    // });

    // Open the DevTools.
    mainWindow.webContents.openDevTools();


    mainWindow.webContents.executeJavaScript("var apiUrl = '" + middlewareHost + "';")
}

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit()
})

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.
