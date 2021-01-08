const sjcl = require("./sjcl");
const BigInteger = require("jsbn").BigInteger;
const SecureRandom = require("jsbn").SecureRandom;

const version = "0_1_25";
const RSAkey =  "10001|E348EBBFF1F0C3FCD819E9433A29D1ED7218D5C48EAFF60F58CE3ADD10F34A3D2FA7FEF3248BFED219534DCC83D45578F24BA9FA870FC4DE900CBCB92E4AB1988F9DCBA93B7392D77E7550B1A9E91F66C79358EAF8808230414A9F3ECB9129F7369E95A462EA99DB52167E4583D06975DE1C28100355B1CEA372B83EDD19DBBFA1A4F1566F656DC8F9D93D4FA5341B4F3D8CA94F56CDF8F666C1D6F4AA077BC998FC3A3F74BED84B34CD6B9888D831B0546272A185F9DA9CF8C09CCDA8344A0F7CE5291D13FE6DF24E5C51FA8E35A0885E7113DB45DB121A54E367E7C9695CE24FE7FCBCA305363B57CFEA8B70DBA192CCD9BC68B2328D3465DD9C2960AEA93F";
const data = '{"expiryMonth":"05","generationtime":"2020-12-26T14:45:40Z","initializeCount":"1","activate":"1","referrer":"https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/pub.v2.4115720109633154.aHR0cHM6Ly93d3cuY291cmlyLmNvbQ.3X7dvjeJWH0uLP2OD2qnErTrsxI0fN-_eT-wBOZfRus/3.2.4/securedFields.html?type=card","sjclStrength":"10"}';

var aeskey = sjcl.random.randomWords(8, 6);
var cipher = AESEncrypt(data, aeskey);
var keybytes = sjcl.codec.bytes.fromBits(aeskey);
var encrypted = RSAEncryptB64(keybytes, RSAkey);
var prefix = "adyenjs_" + version + "$";
var result = [prefix, encrypted, "$", cipher].join("");

console.log(result);

function AESEncrypt(data, key){
    var iv = sjcl.random.randomWords(3, 6);
    var aes = new sjcl.cipher.aes(key);
    var bits = sjcl.codec.utf8String.toBits(data);
    var cipher = sjcl.mode.ccm.encrypt(aes, bits, iv);
    var cipherIV = sjcl.bitArray.concat(iv, cipher);
    return sjcl.codec.base64.fromBits(cipherIV)
}

function RSAEncryptB64(data, key){
    var b = RSAEncrypt(data, key);
    if (b) {
        return hex2b64(b)
    } else {
        return null
    }
};

function RSAEncrypt(data, key){
    var k = key.split("|")
    var exp = k[0];
    var mod = k[1];
    var n = new BigInteger(mod, 16);
    var e = parseInt(exp, 16);
    var a = pkcs1pad2(data, (n.bitLength() + 7) >> 3);
    if (a == null) {
        return null
    }
    var enc = a.modPowInt(e, n);
    if (enc == null) {
        return null
    }
    var d = enc.toString(16);
    if ((d.length & 1) == 0) {
        return d
    } else {
        return "0" + d
    }
}

function pkcs1pad2(c, g) {
    if (g < c.length + 11) {
        console.log("Message too long for RSA");
        return null
    }
    var f = new Array();
    var e = c.length - 1;
    while (e >= 0 && g > 0) {
        f[--g] = c[e--]
    }
    f[--g] = 0;
    var d = new SecureRandom();
    var a = new Array();
    while (g > 2) {
        a[0] = 0;
        while (a[0] == 0) {
            d.nextBytes(a)
        }
        f[--g] = a[0]
    }
    f[--g] = 2;
    f[--g] = 0;
    return new BigInteger(f)
}

function hex2b64(d) {
    var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var b64padchar = "=";
    var b;
    var e;
    var a = "";
    for (b = 0; b + 3 <= d.length; b += 3) {
        e = parseInt(d.substring(b, b + 3), 16);
        a += b64map.charAt(e >> 6) + b64map.charAt(e & 63)
    }
    if (b + 1 == d.length) {
        e = parseInt(d.substring(b, b + 1), 16);
        a += b64map.charAt(e << 2)
    } else {
        if (b + 2 == d.length) {
            e = parseInt(d.substring(b, b + 2), 16);
            a += b64map.charAt(e >> 2) + b64map.charAt((e & 3) << 4)
        }
    }
    while ((a.length & 3) > 0) {
        a += b64padchar
    }
    return a
}
