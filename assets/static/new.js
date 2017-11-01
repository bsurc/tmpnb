var container = document.getElementById("container").innerHTML;
var p = document.getElementById("path").innerHTML;
var token = document.getElementById("token").innerHTML;

xhr = new XMLHttpRequest();
var url = "/status?ping=yes&container="+container;
xhr.open("GET", url, true);
xhr.send(url);
xhr.onreadystatechange = function () {
 if(xhr.readyState === 4 && xhr.status === 200) {
  console.log("container built");
  var link = "<a href="+p+"?token="+token+">Click here to launch your container</a>";
  document.getElementById("status").innerHTML = link;
 } else {
  console.log(xhr.status);
 }
}
setTimeout(xhr.onreadystatechange, 120000);
