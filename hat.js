const fs = require('fs');
const crypto = require('crypto');

const key = Buffer.from('zbNkuNCGSLivpEuep3BcNA==', 'base64');

function aesDecrypt(data, key) {
    const aesoutp2 = crypto.createDecipheriv("aes-128-ecb", key, null);
    let result = aesoutp2.update(data, "base64", "utf8");
    result += aesoutp2.final("utf-8");
    return result;
}

function xor(plaintext, key = '**rVg7EkL~c2`D[aNn') {
    const keyLength = key.length;
    let cipherAscii = '';
    for (let i = 0; i < plaintext.length; i++) {
        cipherAscii += String.fromCharCode(plaintext.charCodeAt(i) ^ key.charCodeAt(i % keyLength));
    }
    return cipherAscii;
}

function parseDecoded(data) {
    var tz, tzKeys;
    var ST = {};
    try {
        tz = JSON.parse(data);
        tzKeys = Object.keys(tz);
    } catch(error) {}

    // Definisi objek untuk menyimpan informasi terdekripsi
    var decryptedInfo = "\n┌───────────────\n│ ha Tunnel (.hat)\n│Channel : https://t.me/mkldec1\n├───────────────\n";

    var connectionMode = [
        "Direct Connection",
        "Custom Payload (TCP)",
        "Custom Host Header (HTTP)",
        "Custom SNI (SSL/TLS)",
        "Imported Config"
    ];

    var connectionMode2 = [
        "SSH",
        "SSL + SSH"
    ];
    var nodeMappings = {
        'xx': 'Random Server, Any Location 🌍',
        'us': 'United States, New York 🇺🇸',
        'ca': 'Canada, Montréal 🇨🇦',
        'de': 'Germany, Frankfurt 🇩🇪',
        'uk': 'United Kingdom, London 🇬🇧',
        'nl': 'Netherlands, Amsterdam 🇳🇱',
        'fr': 'France, Paris 🇫🇷',
        'at': 'Vienne, Austria 🇦🇹',
        'au': 'Australia, Tasmania 🇦🇺',
        'br': 'Brazil, Sao-Paulo 🇧🇷',
        'sg': 'Singapore, Simpang 🇸🇬',
        'in': 'India, Bangalore 🇮🇳',
        'gb': 'Game | EU 🎮'
    };
    const layoutFile = fs.readFileSync("nodehat.json");
    const layout = JSON.parse(layoutFile);

    if (!!tz["configuration"]) {
        ST["connectionMethod"] = connectionMode2[tz["configuration"]["connection_mode"]];
        ST["usePayload"] = tz["configuration"]["using_http_headers"];
        ST["payload"] = tz["configuration"]["http_headers"];
        ST["aotServerGroup"] = tz["configuration"]["server_group_host"];
        ST["enableHTTPProxy"] = tz["configuration"]["using_proxy"];
        ST["aotUseHostAsProxy"] = tz["configuration"]["using_server_hosted_proxy"];
        ST["proxyAddress"] = tz["configuration"]["proxy_host"];
        ST["proxyPort"] = tz["configuration"]["proxy_port"];
        ST["aotServerPort"] = tz["configuration"]["aotServerPort"];
        ST["useSSL"] = tz["configuration"]["using_advssl"];
        ST["sniValue"] = tz["configuration"]["adv_ssl_spoofhost"];
        ST["serverPort"] = tz["configuration"]["adv_ssl_spoofport"];
        ST["udpgwPort"] = tz["configuration"]["vpn_udpgw_port"];
        ST["sshServer"] = tz["configuration"]["server_host"];
        ST["sshUser"] = tz["configuration"]["server_username"];
        ST["sshPassword"] = tz["configuration"]["server_password"];
    }

    if (!!tz["meta"]) {
        ST["note1"] = tz["meta"]["meta_vendor_msg"];
    }

    if (!!tz["profile"]) {
        ST["connectionMethod"] = connectionMode[tz["profile"]["connection_mode"]];
        ST["payload"] = tz["profile"]["custom_payload"];
        ST["hostHeader"] = tz["profile"]["custom_host"];
        ST["sniValue"] = tz["profile"]["custom_sni"];
        ST["aotRealmHost"] = tz["profile"]["use_realm_host"] ? tz["profile"]["realm_host"] : '';
        ST["aotRealmHostValue"] = tz["profile"]["realm_host"];
        ST["aotOverrideHost"] = tz["profile"]["override_primary_host"] ? tz["profile"]["primary_host"] : '';
        ST["aotPrimaryHost"] = tz["profile"]["primary_host"];
        ST["serverPort"] = tz["profile"]["server_port"] ? tz["profile"]["server_port"].toString() : '';
        ST["aotNode"] = tz["profile"]["primary_node"];
        ST["aotBaseTunnel"] = tz["profile"]["base_tunnel"];
    }

    if (!!tz["description"]) {
        ST["note1"] = tz["description"];
    }

    if (!!tz["profilev4"]) {
        ST["connectionMethod"] = connectionMode[tz["profilev4"]["connection_mode"]];
        ST["payload"] = tz["profilev4"]["custom_payload"];
        ST["hostHeader"] = tz["profilev4"]["custom_host"];
        ST["sniValue"] = tz["profilev4"]["custom_sni"];
        ST["aotRealmHost"] = tz["profilev4"]["use_realm_host"] ? tz["profilev4"]["realm_host"] : '';
        ST["aotRealmHostValue"] = tz["profilev4"]["realm_host"];
        ST["aotOverrideHost"] = tz["profilev4"]["override_primary_host"] ? tz["profilev4"]["primary_host"] : '';
        ST["aotPrimaryHost"] = tz["profilev4"]["primary_host"];
        ST["serverPort"] = tz["profilev4"]["server_port"] ? tz["profilev4"]["server_port"].toString() : '';
        ST["aotNode"] = tz["profilev4"]["primary_node"];
        ST["aotBaseTunnel"] = tz["profilev4"]["base_tunnel"];
    }

    if (!!tz["descriptionv4"]) {
        ST["note1"] = tz["descriptionv4"];
    }

    if (!!tz["profilev5"]) {
        ST["connectionMethod"] = xor(Buffer.from(tz["profilev5"]["connection_mode"], 'base64').toString());
        ST["payload"] = xor(Buffer.from(tz["profilev5"]["custom_payload"], 'base64').toString());
        ST["hostHeader"] = xor(Buffer.from(tz["profilev5"]["custom_host"], 'base64').toString());
        ST["sniValue"] = xor(Buffer.from(tz["profilev5"]["custom_sni"], 'base64').toString());
        ST["customresolver"] = tz["profilev5"]["custom_resolver"];
        ST["dnsprimaryhost"] = tz["profilev5"]["dns_primary_host"];
        ST["aotRealmHost"] = tz["profilev5"]["use_realm_host"] ? tz["profilev5"]["realm_host"] : '';
        ST["aotRealmHostValue"] = tz["profilev5"]["realm_host"];
        ST["aotOverrideHost"] = tz["profilev5"]["override_primary_host"] ? tz["profilev5"]["primary_host"] : '';
        ST["aotPrimaryHost"] = tz["profilev5"]["primary_host"];
        ST["serverPort"] = tz["profilev5"]["server_port"] ? tz["profilev5"]["server_port"].toString() : '';
        ST["aotNode"] = tz["profilev5"]["primary_node"];
        ST["aotBaseTunnel"] = tz["profilev5"]["base_tunnel"];
    }

    if (!!tz["descriptionv5"]) {
        ST["note1"] = tz["descriptionv5"];
    }

    if (!!tz["protextras"]) {
        try { ST["antiSniff"] = tz["protextras"]["anti_sniff"].toString() } catch(e) {};
        try { ST["mobileData"] = tz["protextras"]["mobile_data"].toString() } catch(e) {};
        try { ST["blockRoot"] = tz["protextras"]["block_root"].toString() } catch(e) {};
        try { ST["passwordProtected"] = tz["protextras"]["password"].toString() } catch(e) {};
        try { ST["cryptedPasswordValueMD5"] = tz["protextras"]["password_value"].toString() } catch(e) {};
        try { ST["hwidEnabled"] = tz["protextras"]["id_lock"].toString() } catch(e) {};
        try { ST["cryptedHwidValueMD5"] = tz["protextras"]["id_lock_value"].toString() } catch(e) {};
        try { ST["enableExpire"] = tz["protextras"]["expiry"].toString() } catch(e) {};
        try { ST["expireDate"] = new Date(tz["protextras"]["expiry_value"]).toUTCString() } catch(e) {};
    }
    
    if (!!ST["aotNode"] && nodeMappings[ST["aotNode"]]) {
        ST["aotNode"] = nodeMappings[ST["aotNode"]];
    }
    
    Object.keys(layout).forEach(key => {
        if (tz[key]) {
            ST[key] = tz[key];
        }
    });
    
    Object.entries(ST).forEach(([key, value]) => {
        decryptedInfo += `│[۞] ${layout[key]}${value}\n`;
    });
    
    return decryptedInfo;
}

function decryptStage(data) {
    var complete = false;
    var response = {};
    response["content"] = '';    

    try {
        const decryptedData = aesDecrypt(data, key);
        if (decryptedData.indexOf("{\"") !== -1) {
            complete = true;
            response["content"] = parseDecoded(decryptedData);
        }
    } catch (error) {
        console.error(error);
    }
     
    response["content"] += "├───────────────\n├◉ owner:@mujta1n \n├◉ 𝗚𝗥𝗢𝗨𝗣 : @mkldec \n└───────────────\n";

    return response;
}

const args = process.argv.slice(2);

if (args.length !== 1) {
    console.log('Use node hat.js <nama_file_input>');
    process.exit(1);
}

const inputFile = args[0];

fs.readFile(inputFile, 'utf8', (err, data) => {
    if (err) {
        console.error(`Error en el File: ${err}`);
        return;
    }
    
    const decryptedData = decryptStage(data);

    console.log(decryptedData.content);
});
