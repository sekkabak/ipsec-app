let messages = [];
const bodyrequest = {message_type: "", message: ""};

function add_element_to_array(){

      if(document.getElementById("message1").value == "" && document.getElementById("fileone").value == "" ) {
      console.log("musisz coś wyslac!");
      }
      else {
          if (document.getElementById("fileone").value == "" && document.getElementById("message1").value !== "") {
          //nie załączono pliku czyli wysyłam wiadomość textową:
            messages.push(document.getElementById("message1").value);

            bodyrequest.message_type = "txt";
            bodyrequest.message = document.getElementById("message1").value;

            console.log("moj bodyrequest", bodyrequest);

            const requestUrl = "http://127.0.0.1:5000/users/1"
            const Http = new XMLHttpRequest();
            Http.open("POST", requestUrl);
            Http.send(JSON.stringify(bodyrequest));

            document.getElementById("chat-window-1").innerHTML +=
            "<div class='my-message'><span>"+document.getElementById("message1").value+"</span></div>";
            document.getElementById("chat-window-2").innerHTML +=
            "<div class='my-message other-message'><span>"+document.getElementById("message1").value+"</span></div>";
            document.getElementById("message1").value = "";

          }
      else {
          file = document.getElementById("fileone").files[0];
          console.log('to moj plik:', file);

          const requestUrl = "http://127.0.0.1:5000/files/1";
          const httpRequest = new XMLHttpRequest();
          let formData = new FormData();
          formData.append("file", file);
          httpRequest.open("POST", requestUrl);
          httpRequest.send(formData);

          document.getElementById("fileone").value = null;
      }
      }
}


function add_element_to_array_2(){

    if(document.getElementById("message2").value == "" && document.getElementById("filetwo").value == "" ) {
      console.log("musisz coś wyslac!");
      }
      else {
          if (document.getElementById("filetwo").value == "" && document.getElementById("message2").value !== "") {
          //nie załączono pliku czyli wysyłam wiadomość textową:
            messages.push(document.getElementById("message2").value);

            bodyrequest.message_type = "txt";
            bodyrequest.message = document.getElementById("message2").value;

            console.log("moj bodyrequest", bodyrequest);

            const requestUrl = "http://127.0.0.1:5000/users/2"
            const Http = new XMLHttpRequest();
            Http.open("POST", requestUrl);
            Http.send(JSON.stringify(bodyrequest));

            document.getElementById("chat-window-1").innerHTML +=
            "<div class='my-message'><span>"+document.getElementById("message2").value+"</span></div>";
            document.getElementById("chat-window-2").innerHTML +=
            "<div class='my-message other-message'><span>"+document.getElementById("message2").value+"</span></div>";
            document.getElementById("message2").value = "";

          }
      else {
          file = document.getElementById("filetwo").files[0];
          console.log('to moj plik:', file);

          const requestUrl = "http://127.0.0.1:5000/files/2";
          const httpRequest = new XMLHttpRequest();
          let formData = new FormData();
          formData.append("file", file);
          httpRequest.open("POST", requestUrl);
          httpRequest.send(formData);

          document.getElementById("filefile").value = null;
      }
      }
}