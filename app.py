from flask import Flask, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode

app = Flask(__name__)

""" The entire public key string is quite big"""
publicKeyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjQyB0ErPdCx7glBRHoXa5XJXw7uIHPowshdahAJBixBU9v2sKCaLSw" \
                  "C/+5jzVlKELeHG2Z/13T7ICKRTxxwVe9aZ/ZsCN4SpBiDIuM/UmSVzQABlvK1v7pO2UC8+usa53GGT6b2+uufBUN5YkIBclqjN" \
                  "5oVOcX/unzo7SGXk6fQoOL23CRaFTjXviRv6yLl4OFOuLHtJWgp2WYyuUepKpnucLhin8v6kbufiIvLXQI0XGKXzCgEPHDz3QJ" \
                  "q1G7Bmrm3awBvXsZh5zCmDUoorcvG0U6rCA5v8XXrDyrT2se0by9gbLCjENShtLPp+7ECBQH/sufZwyi2jRvzRoyRN6wIDAQAB"
"""These strings are monsterous """
privateKeyString = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCNDIHQSs90LHuCUFEehdrlclfDu4gc+jCyF1qEAkGLEFT2/" \
                   "awoJotLAL/7mPNWUoQt4cbZn/XdPsgIpFPHHBV71pn9mwI3hKkGIMi4z9SZJXNAAGW8rW/uk7ZQLz66xrncYZPpvb6658FQ3l" \
                   "iQgFyWqM3mhU5xf+6fOjtIZeTp9Cg4vbcJFoVONe+JG/rIuXg4U64se0laCnZZjK5R6kqme5wuGKfy/qRu5+Ii8tdAjRcYpfM" \
                   "KAQ8cPPdAmrUbsGaubdrAG9exmHnMKYNSiity8bRTqsIDm/xdesPKtPax7RvL2BssKMQ1KG0s+n7sQIFAf+y59nDKLaNG/NGj" \
                   "JE3rAgMBAAECggEBAItIt4RF69iP+KM1xvU6P2/m2w4ZSQ88bQvgjezgAXNe/FgvJms7rL+zDOJaJqmusIJSezf6gyMo1QXbq" \
                   "DNt4zU4NTa/dI/4e6TmiPAfo5Rb7BRekBiiuG7DBPznuq1cgrtCzHq8efU92KOP/assZsIMDc+/AjiImc45BcO3gzcXAbiHoc" \
                   "1+1HKhbDzSGLGHxc8yrgWpAlpP8J2BdvY22GncAHOySPTMkHT0Nhdi4fLe3U2QSnloZmlSWQQ+IkT8XIq5VGBpa0RJn7SXx1Z" \
                   "HllqPbW67cioG9VMWz+m8lztLB/oMOlqYKhSdJGrLWUz1CUqcnxLGwUEDbBg7TbhPLTECgYEAvtoZfoRox4tBun9RROjGLwAl" \
                   "rMM2i0gujrZdNxJFAaujVgsYcYc7GMl8bV+ntRBpQ7Cl0qejo9uZ6Bi2ajZFUlPN14O296F8tovMUQJ4JZrbmJRIN0g75nghs" \
                   "l91/0zU2fyXEagdQFruA/9D0/B/v3EN/72c6TY1Hyq3cKPN/wMCgYEAvTJI9jp5t2ETM1MQy5PBDSsXpalm40uhb6fkccVxhs" \
                   "PNxTjgdjCxCi+7RxWPWRYEcNMwc/QFiEO7MwwgUGfs+GAHbf0t11Fs1Z/tcNoWpgJXgv6IsOH0Yv3yobNI7k4hhzMrfCoB8pG" \
                   "oA8ttdrEnxBwna/If/XdaSMjSAO9mbPkCgYB90MHlydxZT9Bw5eXpi5q6+Vnc3oRipZ8rrcUdvQmI5GG1I3NlxESNPqasY9bn" \
                   "Yn5ChX2LtcAHEYoQm9oFgumIMH8OiGJiNS9GGDsFXJ9gCwqhN3+0EgaLFL8CHDRprXjUi9P7a9x8xHUMZYeNfIp65kjYQ2Phy" \
                   "j6S4VI1C4eNiQKBgQCNkaX00TaomDP00LAdlNb80oTkSgkaBUqsMPYIh9R2IefELtYOukqPM74v55sW7xmtjumPqkXFe+EExo" \
                   "sbf1hbVgfZLnxxxJTqmLvkGNyfpdrzwyBnMvxaYml+w5fL8Zy2/PwJ8aj5aDJPfJXRHaiC3wpEhK2ZTQi6s8IoPvrmiQKBgB0" \
                   "F+Usz/9an8x4tpMB+IInYZRq26nfqd7tII5mqJsic9PpK3s6Em6806uC9k3MQPTkg547UJa6+UF4aEDTHKNe5Jdqi6mmV2rrH" \
                   "lp46qi2i/Xl3wwJ5zei6cDCAS+A0fvrt3lQ9RtSc4AsrnzGNGRX7OE02DqLOdKu2eAAfbxIm"
decodedPrivateKey = b64decode(privateKeyString)
privateKey = RSA.importKey(decodedPrivateKey)


@app.route('/rec', methods=['GET'])
def request_devices():
    """ This method will allow users to get the list of devices on startup. I am unsure if I will add specific rules for
     this"""
    """TODO ping jemma here and return devices"""
    return " worked"


@app.route('/sec', methods=['POST'])
def request_access():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    encrypted_string = request.form["d"]
    print(encrypted_string)
    privateKey.decrypt(encrypted_string)
    return encrypted_string + " worked"


if __name__ == '__main__':
    app.run(port=9999)

