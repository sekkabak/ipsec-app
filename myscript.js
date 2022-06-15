if (typeof apiUrl === "undefined") {
  apiUrl = "http://127.0.0.1:5000"
}

var local_ip;
var local_port;
var gateway_ip;

async function main() {
  let home = "";
  let chat = "";
  let ping = "";
  let update = "";
  let logs = "";

  await fetch('home.html')
    .then(response => response.text())
    .then(data => home = data);

  await fetch('chat.html')
    .then(response => response.text())
    .then(data => chat = data);

  await fetch('ping.html')
    .then(response => response.text())
    .then(data => ping = data);

  await fetch('update.html')
    .then(response => response.text())
    .then(data => update = data);

  await fetch('logs.html')
    .then(response => response.text())
    .then(data => logs = data);

  const url = apiUrl + "/info";
  await fetch(url)
    .then((response) => response.json())
    .then((data) => {
      local_ip = data.local_ip;
      local_port = data.local_port;
      gateway_ip = data.gateway_ip;
    });

  const routes = [
    { path: '/', component: { template: home }, meta: { local_ip, local_port, gateway_ip } },
    { path: '/chat', component: { template: chat }, meta: { local_ip, local_port, gateway_ip } },
    { path: '/ping', component: { template: ping }, meta: { local_ip, local_port, gateway_ip } },
    { path: '/update', component: { template: update }, meta: { local_ip, local_port, gateway_ip } },
    { path: '/logs', component: { template: logs }, meta: { local_ip, local_port, gateway_ip } },
  ]

  const router = VueRouter.createRouter({
    history: VueRouter.createWebHashHistory(),
    routes,
  })

  const app = Vue.createApp({})
  app.use(router)
  app.mount('#app')
}
main()
// var interval = window.setInterval(update_middleware, 2000);

function do_ping() {
  const ip = document.getElementById("ping-ip").value;
  const url = apiUrl + "/ping/" + ip;
  fetch(url)
    .then((response) => response.text())
    .then((text) => {
      document.getElementById("ping-result").innerHTML = text;
    });
}

function do_update() {
  const ip = document.getElementById("update-ip").value;
  const url = apiUrl + "/update_gateway/" + ip;
  fetch(url)
    .then((response) => response.text())
    .then((text) => {
      document.getElementById("update-result").innerHTML = text;
    });
}

function do_logs() {
  const ip = document.getElementById("logs-ip").value;
  const url = "http://" + ip + ":10500";
  fetch(url)
    .then((response) => response.text())
    .then((text) => {
      document.getElementById("logs-result").innerHTML = text.replace(/\n/g, "<br />");
    });
}

function send_message() {

  if (document.getElementById("message1").value == "" && document.getElementById("fileone").value == "") {
    console.log("musisz coś wyslac!");
  }
  else {
    if (document.getElementById("fileone").value == "" && document.getElementById("message1").value !== "") {
      //nie załączono pliku czyli wysyłam wiadomość textową:
      // messages.push(document.getElementById("message1").value);
      
      const bodyrequest = { message_type: "", message: "", to: ""};
      bodyrequest.message_type = "txt";
      bodyrequest.message = document.getElementById("message1").value;
      bodyrequest.to = document.getElementById("second_user").value;

      fetch(apiUrl + "/send_message", {
        method: 'POST',
        body: JSON.stringify(bodyrequest),
        headers: {
          'Content-type': 'application/json; charset=UTF-8'
        }
      });


      document.getElementById("chat-window-1").innerHTML +=
        "<div class='my-message'><span>" +
        document.getElementById("message1").value +
        "</span></div>";

      document.getElementById("message1").value = "";
    }
    else {
      file = document.getElementById("fileone").files[0];
      let formData = new FormData();
      formData.append("file", file);
      fetch(apiUrl + "/send_file/"+document.getElementById("second_user").value, {
        method: 'POST',
        body: formData
      });

      document.getElementById("fileone").value = null;
    }
  }
}

function isImage(data) {
  let knownTypes = {
    '/': 'data:image/jpg;base64,',
    'i': 'data:image/png;base64,',
    /*ETC*/
    }
    
    let image = new Image()
    
    if(!knownTypes[data[0]]){
      console.log("encoded image didn't match known types");
      return false;
    }else{
      image.src = knownTypes[0]+data
      image.onload = function(){
        //This should load the image so that you can actually check
        //height and width.
        if(image.height === 0 || image.width === 0){
          console.log('encoded image missing width or height');
          return false;
        }
      }
    }
    return true;
}

function makeid(length) {
  var result           = '';
  var characters       = '123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
    result += characters.charAt(Math.floor(Math.random() * 
charactersLength));
 }
 return result;
}

function update_middleware() {
  fetch(apiUrl + "/get_updates")
    .then(response => response.text())
    .then(data => {
      JSON.parse(data).forEach((d) => {
        if(d.type == "txt") {
          document.getElementById("chat-window-1").innerHTML += "<div class='my-message other-message'><span>" + d.message + "</span></div>";
        } else if(d.type == "file" && isImage(d.message)) {
          document.getElementById("chat-window-1").innerHTML += "<div class='my-message other-message'><span> <img style='width: 100%' src='data:image/png;base64, " + d.message + "'/></span></div>";
        } else if(d.type == "mp3") {
          id = makeid(10)
          document.getElementById("chat-window-1").innerHTML += "<div class='my-message other-message'><span><input type='hidden' id='"+id+"' value='" + d.message + "'/><button onclick='playSound("+id+")'>Start</button><button onclick='stopSound()'>Stop</button></span></div>";
        }
      })
    });
}

var context = new AudioContext();
var source = null;
var audioBuffer = null;
// Converts an ArrayBuffer to base64, by converting to string 
// and then using window.btoa' to base64. 
var bufferToBase64 = function (buffer) {
    var bytes = new Uint8Array(buffer);
    var len = buffer.byteLength;
    var binary = "";
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};
var base64ToBuffer = function (buffer) {
    var binary = window.atob(buffer);
    var buffer = new ArrayBuffer(binary.length);
    var bytes = new Uint8Array(buffer);
    for (var i = 0; i < buffer.byteLength; i++) {
        bytes[i] = binary.charCodeAt(i) & 0xFF;
    }
    return buffer;
};
function stopSound() {
    if (source) {
        source.stop(0);
    }
}
function playSound(id) {
    initSound(document.getElementById(id).value)
    source = context.createBufferSource();
    source.buffer = audioBuffer;
    source.loop = false;
    source.connect(context.destination);
    source.start(0); // Play immediately.
}
function initSound(base64String) {
    var audioFromString = base64ToBuffer(base64String);
    context.decodeAudioData(audioFromString, function (buffer) {
        // audioBuffer is global to reuse the decoded audio later.
        audioBuffer = buffer;
        var buttons = document.querySelectorAll('button');
        buttons[0].disabled = false;
        buttons[1].disabled = false;
    }, function (e) {
        console.log('Error decoding file', e);
    });
}