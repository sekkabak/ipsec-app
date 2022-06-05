// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// No Node.js APIs are available in this process because
// `nodeIntegration` is turned off. Use `preload.js` to
// selectively enable features needed in the rendering
// process.

function load_page() {
     document.getElementById("test-form").action = apiUrl + "/send_test";
}

function waitForMiddleware(){
    if(typeof apiUrl !== "undefined"){
        load_page();
    }
    else{
        setTimeout(waitForMiddleware, 50);
    }
}
waitForMiddleware()
















