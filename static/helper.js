function generatePassword() {

  /* Alphabet that avoids: 0O 1I and certain special characters that some people may fail to enter
     when you tell them the password via phone. */
  var chars = "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ!#$%&()*+,-.:;<=>?@";
  var randarray = new Uint16Array(32);
  var retval = "";
  window.crypto.getRandomValues(randarray);
  for (var i = 0, n = chars.length; i < randarray.length; ++i)
    retval += chars.charAt(Math.floor(randarray[i] * n / 65336));
  console.log(retval);
  document.getElementById("password").value = retval;
}


