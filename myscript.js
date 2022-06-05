let messages = [];
const bodyrequest = {message_type: "", message: ""};

function add_element_to_array(){
//    messages.push(document.getElementById("message1").value);
//
//    bodyrequest.message_type = "txt";
//    bodyrequest.message = document.getElementById("message1").value;
//
//    console.log("moj bodyrequest", bodyrequest);
//
//    const requestUrl = "http://127.0.0.1:5000/users/1"
//    const Http = new XMLHttpRequest();
//    Http.open("POST", requestUrl);
//    Http.send(JSON.stringify(bodyrequest));
//
//    document.getElementById("chat-window-1").innerHTML +=
//    "<div class='my-message'><span>"+document.getElementById("message1").value+"</span></div>";
//    document.getElementById("chat-window-2").innerHTML +=
//    "<div class='my-message other-message'><span>"+document.getElementById("message1").value+"</span></div>";
//    document.getElementById("message1").value = "";
      if (document.getElementById("filefile").value == "") {
      console.log('pusto w pliku')
      }
      else {
      file = document.getElementById("filefile").files[0];
      console.log('to moj plik:', file);
      document.getElementById("filefile").value = null;
      }


}


function add_element_to_array_2(){

    messages.push(document.getElementById("message2").value);
    console.log(messages);

    bodyrequest.message_type = "txt";
    bodyrequest.message = document.getElementById("message2").value;

    console.log("moj bodyrequest", bodyrequest);

    const requestUrl = "http://127.0.0.1:5000/users/1"
    const Http = new XMLHttpRequest();
    Http.open("POST", requestUrl);
    Http.send(JSON.stringify(bodyrequest));

    document.getElementById("chat-window-2").innerHTML +=
    "<div class='my-message'><span>"+document.getElementById("message2").value+"</span></div>";
    document.getElementById("chat-window-1").innerHTML +=
    "<div class='my-message other-message'><span>"+document.getElementById("message2").value+"</span></div>";
    document.getElementById("message2").value = "";
}