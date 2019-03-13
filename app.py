import csv
import fileinput

from flask import Flask, request

import casbin
import pandas

import PolicyMethods
import RSAMethods

app = Flask(__name__)


@app.route('/rec', methods=['GET'])
def request_devices():
    """ This method will allow users to get the list of devices on startup. I am unsure if I will add specific rules for
     this"""
    """TODO ping jemma here and return devices"""
    message = 'To be encrypted'

    message = RSAMethods.encrypt_rsa(message)
    return message


@app.route('/sec', methods=['POST'])
def request_access():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    sub = request.form["subject"]
    obj = request.form["object"]
    act = request.form["action"]

    #Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)

    e = casbin.Enforcer("acl.conf", "policies.csv")

    if e.enforce(sub, obj, act):
        # permit alice to read data1
        resp = "pass"
    else:
        # deny the request, show an error
        resp = "You do not have the valid permissions to access devices"

    return resp + " worked"

@app.route('/pol', methods=['POST'])
def update_policies():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    sub = request.form["subject"]
    obj = request.form["object"]
    act = request.form["action"]

    #Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)

    e = casbin.Enforcer("acl.conf", "policies.csv")

    if e.enforce(sub, obj, act):
        if act == "add":
            new_string = "p, " + request.form["new"]
            if PolicyMethods.find_row(new_string):
                resp = "Requested policy already exists"
            else:
                PolicyMethods.add_policy(new_string)
        elif act == "edit":
            old_policy = "p, " + request.form["old"]
            new_policy = "p, " + request.form["new"]
            if PolicyMethods.find_row(old_policy):
                PolicyMethods.edit_policy(old_policy, new_policy)
            else:
                resp = "The policy requested doesnt exist"
        elif act == "del":
            policy_to_delete = "p, " + request.form["old"] # Should read "sub,obj,act"
            PolicyMethods.delete_policy(policy_to_delete)
    else:
        # deny the request, show an error
        resp = "You do not have the valid permissions to access devices"

    return resp + " worked"


if __name__ == '__main__':
    app.run(port=9999)

