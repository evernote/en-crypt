// RC2 JavaScript port
// Copyright (C) Evernote Corporation

var RC2 = {

  keyschedule: function (xkey_string, bits) {

    /* Converting the key string into array of bytes */

    var xkey = xkey_string.split("");
    for (var i = 0; i < xkey.length; i++) {
      xkey[i] = xkey[i].charCodeAt(0);
    }

    /* 256-entry permutation table, probably derived somehow from pi */

    var permute = new Array(
      217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160, 216, 157,
      198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136, 68, 139, 251, 162,
      23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141, 9, 129, 125, 50,
      189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33, 34, 92, 107, 78, 130,
      84, 214, 101, 147, 206, 96, 178, 28, 115, 86, 192, 20, 167, 140, 241, 220,
      18, 117, 202, 31, 59, 190, 228, 209, 66, 61, 212, 48, 163, 60, 182, 38,
      111, 191, 14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188, 148, 67, 3,
      248, 17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47, 200, 102, 30, 215,
      8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172, 53, 77, 106, 42,
      150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208, 94, 4, 24, 164, 236,
      194, 224, 65, 110, 15, 81, 203, 204, 36, 145, 175, 80, 161, 244, 112, 57,
      153, 124, 58, 133, 35, 184, 180, 122, 252, 2, 54, 91, 37, 85, 151, 49,
      45, 93, 250, 152, 227, 138, 146, 174, 5, 223, 41, 16, 103, 108, 186, 201,
      211, 0, 230, 207, 225, 158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169,
      13, 56, 52, 27, 171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46,
      197, 243, 219, 71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193, 173
    );

    if (!bits)
      bits = 1024;

    /* Phase 1: Expand input key to 128 bytes */

    var len = xkey.length;
    for (var i = len; i < 128; i++) {
      xkey[i] = permute[(xkey[i - 1] + xkey[i - len]) & 255];
    }

    /* Phase 2 - reduce effective key size to "bits" */

    var len = (bits + 7) >> 3;
    var i = 128 - len;
    var x = permute[xkey[i] & (255 >> (7 & -bits))];
    xkey[i] = x;
    while (i--) {
      x = permute[x ^ xkey[i + len]];
      xkey[i] = x;
    }

    /* Phase 3 - copy to key array of words in little-endian order */

    var key = new Array(64);
    i = 63;
    do {
      key[i] = (xkey[2 * i] & 255) + (xkey[2 * i + 1] << 8);
    } while (i--);

    return key;
  },

  decrypt_chunk: function (input, xkey) {
    var x76, x54, x32, x10, i;
    x76 = (input.charCodeAt(7) << 8) + input.charCodeAt(6);
    x54 = (input.charCodeAt(5) << 8) + input.charCodeAt(4);
    x32 = (input.charCodeAt(3) << 8) + input.charCodeAt(2);
    x10 = (input.charCodeAt(1) << 8) + input.charCodeAt(0);

    i = 15;
    do {
      x76 &= 65535;
      x76 = (x76 << 11) + (x76 >> 5);
      x76 -= (x10 & ~x54) + (x32 & x54) + xkey[4 * i + 3];

      x54 &= 65535;
      x54 = (x54 << 13) + (x54 >> 3);
      x54 -= (x76 & ~x32) + (x10 & x32) + xkey[4 * i + 2];

      x32 &= 65535;
      x32 = (x32 << 14) + (x32 >> 2);
      x32 -= (x54 & ~x10) + (x76 & x10) + xkey[4 * i + 1];

      x10 &= 65535;
      x10 = (x10 << 15) + (x10 >> 1);
      x10 -= (x32 & ~x76) + (x54 & x76) + xkey[4 * i + 0];

      if (i == 5 || i == 11) {
        x76 -= xkey[x54 & 63];
        x54 -= xkey[x32 & 63];
        x32 -= xkey[x10 & 63];
        x10 -= xkey[x76 & 63];
      }
    } while (i--);

    var out =
      String.fromCharCode(x10 & 255) +
      String.fromCharCode((x10 >> 8) & 255) +
      String.fromCharCode(x32 & 255) +
      String.fromCharCode((x32 >> 8) & 255) +
      String.fromCharCode(x54 & 255) +
      String.fromCharCode((x54 >> 8) & 255) +
      String.fromCharCode(x76 & 255) +
      String.fromCharCode((x76 >> 8) & 255);

    return out;
  },

  decrypt: function (str, key, bits) {
    var out = "";
    var key_array = this.keyschedule(key, bits);

    while (str.length > 0) {
      var chunk = str.slice(0, 8);
      str = str.slice(8);
      out = out + this.decrypt_chunk(chunk, key_array);
    }

    return out;
  }

} // end of RC2 namespace