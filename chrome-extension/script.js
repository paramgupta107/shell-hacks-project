var domain;

var db;
var request = window.indexedDB.open("passwords db", 1);
var privateKey;
var publicKey;
request.onerror = function (event) {
  console.log("error: ");
};

request.onsuccess = function (event) {
  db = request.result;
  console.log("success: " + db);
  changeStateToSetup();
};

request.onupgradeneeded = function (event) {
  var db = event.target.result;
  var objectStore = db.createObjectStore("entries", { keyPath: "id" });
  var objectStore = db.createObjectStore("key", { keyPath: "id" });
};

var password;

async function read() {
  var transaction = db.transaction(["entries"]);
  var objectStore = transaction.objectStore("entries");
  var request = objectStore.get(domain);

  request.onerror = function (event) {
    alert("Unable to retrieve daa from database!");
  };

  request.onsuccess = async function (event) {
    // Do something with the request.result!
    if (request.result) {
      console.log(privateKey)
      const decryptedPassword = await decryptMessage(privateKey, request.result.value);
      password = decryptedPassword;
      console.log(request.result);
      changeStateToPasswordUpdateView();
    } else {
      password = "";
      changeStateToPasswordCreateView();
    }
  };
}

function changeStateToPasswordUpdateView() {
  let main = document.getElementById("main");
  main.innerHTML = `
  <h1>Update</h1>
  <input id="pass" />
  <button id="update">Update</button>
  `;
  let passInput = document.getElementById("pass");
  passInput.value = password;
  let create = document.getElementById("update");
  create.addEventListener("click", createPassword);
}

function changeStateToPasswordCreateView() {
  let main = document.getElementById("main");
  main.innerHTML = `
  <h1>Password</h1>
  <input id="pass" />
  <button id="create">Save</button>
  `;
  let passInput = document.getElementById("pass");
  passInput.value = password;
  let create = document.getElementById("create");
  create.addEventListener("click", createPassword);
}

async function createPassword() {
  let passInput = document.getElementById("pass");
  const encryptedPassword = await encryptMessage(publicKey, passInput.value)
  var request = db
    .transaction(["entries"], "readwrite")
    .objectStore("entries")
    .put({ id: domain, value: encryptedPassword });

  request.onsuccess = function (event) {
    console.log("value has been added to your database.");
    password = passInput.value;
    changeStateToPasswordUpdateView();
  };

  request.onerror = function (event) {
    console.log("Unable to add value in your database! ");
  };
}

function changeStateToMain() {
  let main = document.getElementById("main");
  main.innerHTML = `
  <h1>Enter master password</h1>
  <input id="master" />
  <button id="manage">Manage Password</button>
  `;
  var button = document.getElementById("manage");
  button.addEventListener("click", unwrapMaster);
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs[0];
    var url = new URL(tab.url);
    domain = url.hostname;
    var protocol = url.protocol;
    // `domain` now has a value like 'example.com'
    var element = document.getElementById("title");
    // element.innerText = domain;
    if (protocol !== "https:") {
      let main = document.getElementById("main");
      main.innerHTML = `
      <h1>Connection to website not secure</h1>`;
    }
  });
}

function changeStateToSetup() {
  var transaction = db.transaction(["key"]);
  var objectStore = transaction.objectStore("key");
  var request = objectStore.get(0);

  request.onerror = function (event) {
    alert("Unable to retrieve data from database!");
  };

  request.onsuccess = function (event) {
    // Do something with the request.result!
    if (request.result) {
      changeStateToMain();
    } else {
      changeStateToRegister();
    }
  };
}

function changeStateToRegister() {
  let main = document.getElementById("main");
  main.innerHTML = `
  <h1>Set Master Password</h1>
  <input id="master" />
  <button id="set">Set</button>
  `;
  let set = document.getElementById("set");
  set.addEventListener("click", setKey);
}

async function setKey() {
  let masterInput = document.getElementById("master");

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      // Consider using a 4096-bit key for systems that require long-term security
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const aes_key = await gen_aes_key(masterInput.value);

  const wrapped_private_key = await window.crypto.subtle.wrapKey(
    "jwk",
    keyPair.privateKey,
    aes_key,
    { name: "AES-GCM", iv: new Uint8Array([1, 2]), length:256}
  );
  console.log(wrapped_private_key);

  var request = db
    .transaction(["key"], "readwrite")
    .objectStore("key")
    .put({ id: 0, public: keyPair.publicKey, private: wrapped_private_key });

  request.onsuccess = function (event) {
    console.log("value has been added to your database.");
    changeStateToMain();
  };

  request.onerror = function (event) {
    console.log("Unable to add value in your database! ");
  };
}

async function gen_aes_key(aes_key) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(aes_key),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  return (aes_key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array([5, 3, 53, 543]),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  ));
}

function unwrapMaster() {
  var transaction = db.transaction(["key"]);
  var objectStore = transaction.objectStore("key");
  var request = objectStore.get(0);

  request.onerror = function (event) {
    alert("Unable to retrieve data from database!");
  };

  request.onsuccess = async function (event) {
    // Do something with the request.result!
    if (request.result) {
      publicKey = request.result.public;
      const wrapedKey = request.result.private;
      console.log(wrapedKey);
      var master = document.getElementById("master");
      const aes_key = await gen_aes_key(master.value);

      privateKey = await window.crypto.subtle.unwrapKey(
        "jwk",
        wrapedKey,
        aes_key,
        { name: "AES-GCM", iv: new Uint8Array([1, 2]), length:256 },
        {
          name: "RSA-OAEP",
          // Consider using a 4096-bit key for systems that require long-term security
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ['decrypt']
      );
      read();
    }
  };
}

function getMessageEncoding(message) {

  let enc = new TextEncoder();
  return enc.encode(message);
}

function encryptMessage(key, message) {
  let encoded = getMessageEncoding(message);
  // iv will be needed for decryption
  return window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    key,
    encoded,
  );
}

async function decryptMessage(key, ciphertext) {
    let decrypted = await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      key,
      ciphertext
    );

    let dec = new TextDecoder();
    return dec.decode(decrypted);

}
