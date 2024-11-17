const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto"); // pakai modul crypto untuk generate pasangan key rsa

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();
let privateKey = "";
let publicKey = "";

// Generate RSA key pair
function generateKeyPair() { // untuk generate pasangan key 
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, // pakai 2048 agar aman dan kuat
    publicKeyEncoding: { type: "spki", format: "pem" }, // public dan private key menggunakan format pem
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function encryptMessage(message, targetPublicKey) {
  // untuk mengenkripsi pesan dengan kunci publik
  // pesan dikonversi menjadi buffer untuk proses enkripsi
  return crypto.publicEncrypt(targetPublicKey, Buffer.from(message)).toString("base64");
}

function decryptMessage(ciphertext) {
  try {
    // pesan di decrypt menggunakan kunci privat
    // ciphertext dikonversi dari format base64 ke buffer.
    return crypto.privateDecrypt(privateKey, Buffer.from(ciphertext, "base64")).toString();
  } catch (err) {
    return "Failed to decrypt message.";
  }
}

({ publicKey, privateKey } = generateKeyPair()); // untuk generate private dan public key nya

socket.on("connect", () => {
  console.log("Connected to the server");

  socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`\nThere are currently ${users.size} users in the chat`);
    rl.prompt();

    rl.question("Enter your username: ", (input) => {
      username = input;
      console.log(`Welcome, ${username} to the chat`);

      socket.emit("registerPublicKey", {
        username,
        publicKey,
      });

      rl.prompt();

      rl.on("line", (message) => {
        if (message.trim()) {
          if ((match = message.match(/^!secret (\w+)$/))) {
            targetUsername = match[1];
            console.log(`Now secretly chatting with ${targetUsername}`);
          } else if (message.match(/^!exit$/)) {
            console.log(`No more secretly chatting with ${targetUsername}`);
            targetUsername = "";
          } else {
            let encryptedMessage = message;
            if (targetUsername) {
              // mengambil kunci publik dari target user
              const targetPublicKey = users.get(targetUsername); 
              if (targetPublicKey) {
                // pesan di encrypt menggunakan public key nya target user
                encryptedMessage = encryptMessage(message, targetPublicKey); 
              } else {
                console.log(`Public key for ${targetUsername} not found.`);
              }
            }
            socket.emit("message", { username, message: encryptedMessage, targetUsername }); // dikirim pesan yang di encrypt 
          }
        }
        rl.prompt();
      });
    });
  });
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, targetUsername } = data;

  if (username === senderUsername && targetUsername) {
    // jika pengirim adalah user saat ini dan pesan rahasia (targetUsername di-set), 
    // jangan tampilkan ciphertext di pengirim.
    return;
  }

  if (targetUsername && targetUsername !== username) { // cek jika username tidak sesuai dengan target user nya
    console.log(`${senderUsername}: ${senderMessage}`); // tampilkan ciphertext
  } else {
    let outputMessage;
    if (targetUsername === username) { // cek jika username sesuai dengan target user nya
      outputMessage = decryptMessage(senderMessage); // pesan di decrypt (berupa tampilan pesan)
    } else { // cek jika mode public atau bukan mode !secret
      outputMessage = senderMessage;
    }

    console.log(`${senderUsername}: ${outputMessage}`); // menampilkan pesan nya
  }

  rl.prompt();
});



socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
