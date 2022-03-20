import hashlib
import os
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask_mqtt import Mqtt
import uuid
import ast
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask, render_template, request
from collections import defaultdict
import hmac

# Parámetros para configurar Flask y lanzar la interfaz web
app = Flask(__name__)
app.config['MQTT_BROKER_URL'] = 'public.cloud.shiftr.io' # URL del broker mqtt
app.config['MQTT_BROKER_PORT'] = 1883 # Puerto del broker mqtt
app.config['MQTT_USERNAME'] = 'public' # Usuario del broker mqtt
app.config['MQTT_PASSWORD'] = 'public' # Contraseña del broker mqtt
app.config['MQTT_REFRESH_TIME'] = 1.0  # refresh time in seconds
mqtt = Mqtt(app) # Crea una instancia del broker mqtt

# Variables
myID = str(uuid.uuid1()) # Identificador de la plataforma IoT
idsSet = set() # Conjunto de identificadores de los dispositivos IoT Vivos
iotMap = dict() # Mapeado de cada identificador de dispositivo IoT junto con su clave secreta compartida
privateIotMap = dict() # Mapeado de cada identificador de dispositivo IoT junto con la clave privada de DH
dataTable = defaultdict(set) # Map of sets para representar los mensajes de cada dispositivo

# Clave privada maestra de la platarforma IoT, IMPORTANTE: esta clave debería guardarse de otra forma y no hardcodearla
webUI_private_master_key = serialization.load_pem_private_key(
    b'-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDYv8n1wChIAfmP\nX9fFIyk//VfGQkm5ohmksjL7rczCDZ6SA9thefFCALPEcFafe+GrgIjv8JFetjWB\neJ7NSKsoQ6ifJQTB33Wk/TXQfAQEHteaCAGzxGR1fqZvM/InNFFwQpXHtmtU4/cf\np0VXjtewPz5bkWxPxB2qMU40AZzC2cmfPFfKsOnjx2KJeseXflyPjO7PwUtATdiS\nggaRqSWVLDTk/aVDPd9w6VNLZaO2ftrlHVbZrBNvX1Nt4p2J/Vc1yVCXDKUhYRcQ\n0h97DeE+ZgCkGILJ9s/JDhauz/dwcpMtiBoqZaYZw2SZCO40wWbApoWxzNX9JHsi\noF4LAcsRAgMBAAECggEAMghTfj7VDYonKUlebUsognTghgtXKVqZwMLBsgb0dPbf\n26S4R0/2uN2goX+s/zOBbC1HbtuBMvOsdi55ublEiQ7VJadN6dLDPUqV2YJHCwxz\niELA4dY7ukN598Ft7E7PXbKBEJCzRe05Zj0ebI+0iiKPKmPvNJp4noizHJ4iqXdf\njoFJdeuuQSDNQo2BZPpSEmNXab0grlmYaMCgm0+0RDtmemNK+cjy+3OOMtt9HEaJ\n4HLR/Grrid3ceiruNJ8J0GlbYQ5dHE1VUdFgklNhAkryUZzWGZBLeVXXdq5YdRkQ\nQvcpE0glt5Q3PwFzd13wlneRONFC8Hz4T4nuoEfY4QKBgQD2fdno8v7MVrEGwkrV\nRk0QVKtpPPVS+/j8WSVAbNdXU6zp62LO+tYlEk8GBIsHTB/0R7mKObPa2jYYPHSq\nldSqZtk9P5VIzd3BOxjM9ecmTH/cmg7GX/P0T2MQbnadGw1nSppduMXfP0/7jM7M\nBeZx+4j+ZfEhtRyh6ItqrB2CawKBgQDhHDnR8+cc7aC+AX0Ll0FsgXTrBWKazBPD\nrk/BNBytStgOF6D5QoR7nXFjxsH5BKPW7ZbuWNAmXGn4UNjkNIKXstxhr0wSGApq\nSpPIPIWS6ZLwygS7W7AxAbNngv38uqHdkdjRytFO6bdBMSxrI1MJiyu/m2skNZ7q\nv+7OGq/fcwKBgB80tabJRLrH6ueJJ4IywUTlA0Jyhjh4UABapN2wKd8TZ9vBgiPk\nG8JbvAduAc/tsknx3qqCPaPiZmDRHpAOIftkw/H+H7802PNCsRQZuabenn1mP6Kb\nuT3f4xHMelXPe/XsuvhMkTh/Qnf9Tp0DzjX1+1UBwPJchIB2+VeK7L17AoGAHuWD\n3hgu2V6YGFwV8JhTB3SBOpyjmwF1mP78vVTMttA19UEy++MwUdMbNAmcp/QGFMLJ\nW29fKlS2yrk1+6RlZDLNYq7vrvATxeD0haAg6Tgbzea8XYbJGQDVwdhNyflHrCSP\ncMP4lG8pks4P/ah8hivO1l6bhv3BERFE0o8BIpcCgYBgHFhDOVFDyx/sXvEM75HJ\nJRa3x7ezr57U83cPpzvxCpApmy4D6KVTVFfiJ/XLbZqsORdPKrqfbumxLo95mbRr\n8hWf0Z2ChViihM5gOfUSmsyO7gVxjhEyNiHV4MizMHtxRKXEBhcz9p1fMrvx8SaJ\nrET6NOlOM0oAIJWadGIzAg==\n-----END PRIVATE KEY-----\n',
    password=None)

# Clave publica del dispositivo IoT IMPORTANTE: cada dispositivo debería de tener su clave pública
iotSensor_public_master_key = serialization.load_pem_public_key(
    b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1kuHOCHclVMplZ9B/4kv\n40aSgtMnuWX/wK+lr0lK2+aMiIZGtNbso8gnOeraK4/U0jMDJVusJdB7ahZsRU5T\nTBJ9B+YxmZEuTwweYoSClMzzaRtVGRmZZF2ygejZdBpw3MFYV0z6FFx87HrUx6+J\n47/7gNXoNpvSmmafFte6xpOgop0jgP/e4ID3TITDDRpCWR3SPqiXcefBDkJ0WOMU\nIPfGAEzUVLLqKaKBDpM0c/BpsDGGXIC6l9rtAVYTMUTaDhnMtl8SKKSg5NILwJ7P\n6Vi/fTHlmikxYklB/OckvL6+bb/leAi99u/vTUiBukfvuv5Ufu7FPBpy6i+siqk6\nxwIDAQAB\n-----END PUBLIC KEY-----\n')


# Metodo para conectar con el broker mqtt
@mqtt.on_connect()
def on_connect(client, userdata, flags, rc):
    print("Connected to server")

    # Suscripción al topic "UMA/IDs" para recibir los identificadores de los dispositivos vivos
    mqtt.subscribe("UMA/IDs")


# Metodo para gestionar los mensajes recibidos en función de los topics suscritos
@mqtt.on_message()
def on_message(client, userdata, msg):
    # Topic del mensaje
    topic = msg.topic
    print(topic)
    # Decodifica el payload recibido
    payload = msg.payload.decode("utf-8", "ignore")

    if topic == "UMA/IDs":
        # Añade el ID del dispositivo IoT al conjunto "idsSet"
        idsSet.add(payload)

    # Por cada valor en el idsSet (no debe utilizarse el mapa porque no se ha hecho pair aun)
    for value in idsSet:
        if topic == "UMA/"+value+"/DH":
            # Parsea los bytes recibidos a "Json"
            payload_dict = ast.literal_eval(payload)

            # Verifica la firma para autenticar el mensaje enviado por el dispositivo IoT
            if not verify_message(iotSensor_public_master_key, payload_dict["HMAC"], payload_dict["data"]):
                return

            # Parsea los bytes recibidos a "Json"
            payload_dict = ast.literal_eval(payload_dict["data"].decode("utf-8"))

            # Si contiene el valor de la clave publica del dispositivo IoT, entonces el intercambio ha ido bien
            if "b_public_key_pem" in payload_dict:
                # Deserializa la clave enviada por el dispositivo IoT
                b_pk = load_pem_public_key(payload_dict["b_public_key_pem"])

                if isinstance(b_pk, dh.DHPublicKey):
                    # Calcula la clave compartida
                    shared_key = privateIotMap[payload_dict["id"]].exchange(b_pk)

                    # Mapea el ID junto con la clave compartida en la estructura "iotMap"
                    iotMap[payload_dict["id"]] = shared_key

                    # Suscripción al topic "UMA/"+payload_dict["id"]+myID+"/Data" para empezar a recibir los datos
                    # cifrados por el dispositivo IoT que se acaba de asociar --> "pairing"
                    mqtt.subscribe("UMA/"+payload_dict["id"]+myID+"/Data")

    for key in iotMap:
        if topic == "UMA/" + key + myID + "/Data":
            # Parsea los bytes recibidos a "Json"
            payload_dict = ast.literal_eval(payload)

            # Clave compartida con la plataforma IoT mapeada despues del pairing y el DH con HMAC
            # Se utilizan 32 bytes ya que la clave compartida mediante DH es de 64 y AES no soporta este tamaño de clave
            decipher_key = iotMap[key][0:32]

            # Descifra el mensaje dada una clave y un objeto json
            decipher_text = decipher_message(decipher_key, payload_dict)

            # Crea un hash para autenticar el mensaje (formato IPSEC)
            h = hmac.new(decipher_key, payload_dict["cipher_text"], hashlib.sha256)

            if not h.digest() == payload_dict["HMAC"]:
                return

            # Añade una nueva entrada de datos correspondiente al ID del dispositivo IoT que manda los datos
            dataTable[key].add("{\"Time\": "+datetime.now().strftime("%d/%m/%Y %H:%M:%S")+", "
                                "\"Data\": "+decipher_text.hex()+"}")

            # Printea por consola la tabla
            print(dataTable[key])


# Método para recargar la interfaz web con la ultima información recibida
@app.route('/Reload_sensors', methods=['POST'])
def reload_sensors():
    return render_template('app_frontend.html', sensor_list=list(idsSet), sensor_paired_list=iotMap.keys())


# Metodo para eliminar un dispositivo IoT asociado anteriormente
@app.route('/Disconnect_to_sensor', methods=['POST'])
def disconnect_to_sensor():
    id_sensor = request.form['sensor_removing']

    # Crear un mensaje en formato "Json" con los valores serializados y el ID de la plataforma
    data = {'Remove': True, 'id': myID}

    # Pasa el "Json" a formato bytes UTF-8
    data = bytes(str(data), "utf-8")

    # Clave compartida con la plataforma IoT mapeada despues del pairing y el DH con HMAC
    # Se utilizan 32 bytes ya que la clave compartida mediante DH es de 64 y AES no soporta este tamaño de clave
    cipher_key = iotMap[id_sensor][0:32]

    # Crea un hash para autenticar el mensaje (formato IPSEC)
    h = hmac.new(cipher_key, data, hashlib.sha256)

    # Crea un "Json" con el mensaje y la firma sobre el mensaje
    final_data = {'data': data, 'HMAC': h.digest()}

    # Pasa el "Json" a formato bytes UTF-8
    final_data = bytes(str(final_data), "utf-8")

    # Envio del mensaje
    mqtt.publish("UMA/" + id_sensor + "/Remove", final_data)

    # Eliminar la referencia en el mapa entre el ID del dispositivo IoT y su clave compartida
    iotMap.pop(id_sensor)
    privateIotMap.pop(id_sensor)

    return render_template('app_frontend.html', sensor_list=list(idsSet), sensor_paired_list=iotMap.keys())


# Metodo para asociarse con un dispositivo IoT
@app.route('/Connect_to_sensor', methods=['POST'])
def connect_to_sensor():
    id_sensor = request.form['sensor_connection']

    # Suscripcion al topic "UMA/"+id_sensor+"/DH" para inciar el intercambio de claves mediante DH con HMAC
    mqtt.subscribe("UMA/"+id_sensor+"/DH")

    # Generar parámetros mediante DH con HMAC
    parameters = dh.generate_parameters(generator=2, key_size=512)

    # Generar claves privadas y públicas mediante DH con HMAC
    a_private_key = parameters.generate_private_key()
    a_public_key = a_private_key.public_key()
    privateIotMap[id_sensor] = a_private_key

    # Serializar los parámetros y la clave publica para enviarla al otro endpoint
    params_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
    a_public_key_pem = a_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # Crear un mensaje en formato "Json" con los valores serializados y el ID de la plataforma
    data = {'params_pem':params_pem, 'a_public_key_pem':a_public_key_pem, 'id':myID}

    # Pasa el "Json" a formato bytes UTF-8
    data = bytes(str(data),"utf-8")

    # Firma digital con la clave privada de la plataforma IoT
    signature = sign_message(webUI_private_master_key, data)

    # Crea un "Json" con el mensaje y la firma sobre el mensaje
    final_data = {'data': data, 'HMAC': signature}

    # Pasa el "Json" a formato bytes UTF-8
    final_data = bytes(str(final_data),"utf-8")

    # Envio del mensaje
    mqtt.publish("UMA/"+id_sensor+"/DH", final_data)

    return render_template('app_frontend.html', sensor_list=list(idsSet), sensor_paired_list=iotMap.keys())


# Metodo para firmar un mensaje en función de un key
def sign_message(key, msg):
    signature = key.sign(
        data=msg,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    return signature


# Metodo para verificar un mensaje
def verify_message(key, signature, msg):
    try:
        key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        # Si la excepcion salta, sale del metodo sin mapear nada ya que el mensaje ha sido modificado
        return False


# Metodo para cifrar un mensaje dada una clave y un texto en plano
def cipher_message(cipher_key, plain_text):
    # Vector de inicialización para el modo de cifrado
    iv = os.urandom(32)

    # Crea un objeto cifrador mediante el metodo de operacion ECB
    encryptor_ecb = Cipher(algorithms.AES(cipher_key), modes.ECB()).encryptor()

    # Cifra el texto con el cifrador
    cipher_text = encryptor_ecb.update(plain_text)
    encryptor_ecb.finalize()

    # Crear un mensaje en formato "Json" con el texto cifrado
    data = {'cipher_text': cipher_text}

    return data


# Metodo para descifrar un mensaje dada una clave y un objeto Json
def decipher_message(decipher_key, payload_dict):

    # Crea un objeto descifrador mediante el metodo de operacion ECB
    decipher_ecb = Cipher(algorithms.AES(decipher_key), modes.ECB())

    # Descifra el texto con el descifrador
    decrypt_ecb = decipher_ecb.decryptor()
    decipher_text = decrypt_ecb.update(payload_dict["cipher_text"])
    decrypt_ecb.finalize()

    return decipher_text


# Raiz de la interfaz web
@app.route("/")
def hello():
    return render_template('app_frontend.html', sensor_list=list(idsSet), sensor_paired_list=iotMap.keys())


# Metodo principal
if __name__ == "__main__":
    app.run()
