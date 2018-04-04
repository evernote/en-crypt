// EN-Crypt helper logic
// Copyright (C) Evernote Corporation

var ENCrypt = {

  EN_RC2_ENCRYPTION_KEYSIZE: 64,

  decrypt: function (base64str, passphrase) {

    // Password is UTF8-encoded before MD5 is calculated.
    // MD5 is used in raw (not hex-encoded) form.

    var str = RC2.decrypt(Base64.decode(base64str), MD5_hash(Utf8.encode(passphrase)), this.EN_RC2_ENCRYPTION_KEYSIZE);

    // First 4 chars of the string is the HEX-representation of the upper-byte of the CRC32 of the string.
    // If CRC32 is valid, we return the decoded string, otherwise return null

    var crc = str.slice(0, 4);
    str = str.slice(4);


    var realcrc = crc32(str) ^ (-1); // XOR with -1 to match the implementation in Evernote
    realcrc = realcrc >>> 0; // trick to make value an uint before converting to hex
    realcrc = this.d2h(realcrc).substring(0, 4).toUpperCase(); // convert to hex, take only first 4 uppercase hex digits to compare

    if (realcrc == crc) {

      // Get rid of zero symbols at the end of the string, if any

      while ((str.length > 0) && (str.charCodeAt(str.length - 1) == 0))
        str = str.slice(0, str.length - 1);

      // Return Unicode string

      return Utf8.decode(str);

    } else {
      return null;
    }
  },

  d2h: function (d) {
    return d.toString(16);
  },

  decrypt_prompt: function (hint, encrypted_fragment) {

    var prompt_string = "Enter the passphrase to decrypt the content.";
    if (hint != "") {
      prompt_string += "\n" + "Passphrase hint: " + hint;
    }
    var passphrase = prompt(prompt_string, '');

    if (passphrase == "") return;

    var decrypted_fragment = ENCrypt.decrypt(encrypted_fragment, passphrase);
    if (decrypted_fragment == null) {
      alert("The passphrase is incorrect.");
    } else {
      alert("Decoded fragment: " + decrypted_fragment);
    }
  }

} // end of ENCrypt namespace
