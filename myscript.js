let messages = [];


//const firstInput = document.getElementById("message1");

function add_element_to_array(){
    // var today = new Date();
    // var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
    messages.push(document.getElementById("message1").value);
    console.log(messages);

    document.getElementById("chat-window-1").innerHTML +=
    "<div class='my-message'><span>"+document.getElementById("message1").value+"</span></div>";
    document.getElementById("chat-window-2").innerHTML +=
    "<div class='my-message other-message'><span>"+document.getElementById("message1").value+"</span></div>";
    document.getElementById("message1").value = "";
//    console.log(time + " / " + messages[messages.length -1]);
}

function add_element_to_array_2(){
    // var today = new Date();
    // var minutes = String(today.getMinutes()).padStart(2, '0');
    // var time = today.getHours() + ":" + minutes + ":" + today.getSeconds();
    messages.push(document.getElementById("message2").value);
    console.log(messages);

    document.getElementById("chat-window-2").innerHTML +=
    "<div class='my-message'><span>"+document.getElementById("message2").value+"</span></div>";
    document.getElementById("chat-window-1").innerHTML +=
    "<div class='my-message other-message'><span>"+document.getElementById("message2").value+"</span></div>";
    document.getElementById("message2").value = "";
//    console.log(time + messages[messages.length -1]);
}