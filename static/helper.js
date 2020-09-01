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


Dropzone.options.myDropzone = {
    init: function() {
        // redirect after queue complete
        // upload queue when button click
        // custom init code
    },
    // click upload options
    uploadMultiple: true,
    parallelUploads: 10,
    paramName: "file", // The name that will be used to transfer the file
    maxFilesize: 128, // MB
    acceptedFiles: "",
    maxFiles: null,
    dictDefaultMessage: "Ziehe die Dateien hier hin, um sie hochzuladen oder klicken Sie zur Auswahl.", // message display on drop area
    dictFallbackMessage: "Your browser does not support drag'n'drop file uploads.",
    dictInvalidFileType: "You can't upload files of this type.",
    dictFileTooBig: "File is too big {{filesize}}. Max filesize: {{maxFilesize}}MiB.",
    dictResponseError: "Server error: {{statusCode}}",
    dictMaxFilesExceeded: "You can't upload any more files.",
    dictCancelUpload: "Cancel upload",
    dictRemoveFile: "Remove file",
    dictCancelUploadConfirmation: "You really want to delete this file?",
    dictUploadCanceled: "Upload canceled",
    // custom options code
};

window.onload = function() {
    b = document.getElementById("generatePassword");
    if (b != null) { b.onclick = function() { generatePassword() }; }
		     
    b = document.getElementById("copyPassword");
    if (b != null) { b.onclick = function() { copyPassword() }; }

    for (let b of document.getElementsByName("edit")) {
	b.onclick = function() { document.getElementById('user').value = b.value };
    }
    
    for (let f of document.getElementsByName("del-confirm")) {
	f.onsubmit = function() { return confirm('Sind Sie sicher?'); };
    }
};
