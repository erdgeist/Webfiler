function generatePassword() {

  /* Alphabet that avoids: 0O 1I and certain special characters that some people may fail to enter
     when you tell them the password via phone. */
  var chars = "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ!#$%&()*+,-.:;<=>?@";
  var randarray = new Uint16Array(32);
  var retval = "";
  window.crypto.getRandomValues(randarray);
  for (var i = 0, n = chars.length; i < randarray.length; ++i)
    retval += chars.charAt(Math.floor(randarray[i] * n / 65336));
  document.getElementById("password").value = retval;
}


function copyPassword() {
    navigator.clipboard.writeText(document.getElementById("password").value)

    setTimeout(() => {
	navigator.clipboard.writeText('password removed from clipboard after timeout')
    }, 30000);
}


window.onload = function() {
    b = document.getElementById("generatePassword");
    if (b != null) { b.onclick = function() { generatePassword() }; }
		     
    b = document.getElementById("copyPassword");
    if (b != null) { b.onclick = function() { copyPassword() }; }

    for (let b of document.getElementsByName("edit")) {
	b.onclick = function() { document.getElementById('user').value = b.value };
    }
};
