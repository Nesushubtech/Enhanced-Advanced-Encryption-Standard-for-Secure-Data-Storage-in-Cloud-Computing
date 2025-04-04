from flask import Flask, request, render_template, send_file, session, redirect, url_for
import os
import firebase_admin
from firebase_admin import credentials, firestore, storage
import pyrebase
from Crypto.Cipher import AES
import requests

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this to a secure key

# Firebase Configuration (Add your Firebase details)
firebaseConfig = {
    "apiKey": "YOUR_API_KEY",
    "authDomain": "YOUR_PROJECT.firebaseapp.com",
    "databaseURL": "https://YOUR_PROJECT.firebaseio.com",
    "projectId": "YOUR_PROJECT",
    "storageBucket": "YOUR_PROJECT.appspot.com",
    "messagingSenderId": "YOUR_MESSAGING_SENDER_ID",
    "appId": "YOUR_APP_ID",
}

# Initialize Firebase
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {"storageBucket": firebaseConfig["storageBucket"]})

# Firestore & Storage
db = firestore.client()
pb = pyrebase.initialize_app(firebaseConfig)
storage_ref = pb.storage()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        session['user'] = email  # Simulating login (Use Firebase Auth for real implementation)
        return redirect(url_for('upload_file'))
    return render_template('login.html')

@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    email = session['user']

    if request.method == 'POST':
        ori_file = request.files['upload_file']
        file_name = request.form.get('file_name')
        cloud_name = f"{email}/{file_name}"

        # Generate AES key
        aes_key = os.urandom(16)

        # Encrypt the file
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(ori_file.read())

        # Store AES key securely in Firestore
        db.collection("keys").document(email).set({file_name: aes_key.hex()}, merge=True)

        # Upload encrypted file to Firebase Storage
        storage_ref.child(cloud_name).put(ciphertext)

        return render_template('success.html')

    return render_template('upload.html')

@app.route('/download', methods=['POST', 'GET'])
def download_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    email = session['user']

    if request.method == 'POST':
        file_name = request.form.get('download_file_name')
        cloud_name = f"{email}/{file_name}"

        # Retrieve AES key from Firestore
        key_doc = db.collection("keys").document(email).get()
        if not key_doc.exists or file_name not in key_doc.to_dict():
            return "Key not found!", 404

        aes_key = bytes.fromhex(key_doc.to_dict()[file_name])

        # Download encrypted file from Firebase Storage
        encrypted_file_url = storage_ref.child(cloud_name).get_url(None)
        response = requests.get(encrypted_file_url)
        encrypted_data = response.content

        # Decrypt the file
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_file = cipher.decrypt(ciphertext)

        # Save the decrypted file
        output_path = f"downloads/{file_name}"
        os.makedirs("downloads", exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(decrypted_file)

        return send_file(output_path, as_attachment=True)

    return render_template('download.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
