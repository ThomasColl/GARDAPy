import csv
import fileinput
import json

import requests

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
    """TODO ping openHAB here and return devices"""
    r = requests.get("http://localhost:8080/rest/items?recursive=false")
    raw_items = json.loads(r.text)
    items = []
    for item in raw_items:
        items.append(item["name"])

    # message = RSAMethods.encrypt_rsa(items)
    # return message
    return json.dumps(items)


@app.route('/recs', methods=['GET'])
def request_devices2():
    """ This method will allow users to get the list of devices on startup. I am unsure if I will add specific rules for
     this"""
    """TODO ping jemma here and return devices"""

    value = request.form["key"]
    r = requests.get("http://localhost:8080/rest/items/" + str(value))
    raw_items = json.loads(r.text)
    items = raw_items["type"]
    # message = RSAMethods.encrypt_rsa(items)
    # return message
    return json.dumps(items)


@app.route('/sec', methods=['POST'])
def request_access():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    req = request.get_json()
    print(req)
    val = req["key"]
    opt = req["option"]
    sub = req["subject"]
    obj = req["object"]
    act = req["action"]

    #Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)

    e = casbin.Enforcer("acl.conf", "policies.csv")

    if e.enforce(sub, obj, act):
        # permit alice to read data1
        r = requests.put("http://localhost:8080/rest/items/" + str(val) + "/state", data=str(opt).upper())
        resp = "pass"
    else:
        # deny the request, show an error
        resp = "You do not have the valid permissions to access devices"

    return resp


@app.route('/polr')
def request_policies():
    return json.dumps(PolicyMethods.get_valid_users())


@app.route('/poll')
def request_policies1():
    return json.dumps(PolicyMethods.get_list())


@app.route('/pol', methods=['POST'])
def update_policies():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    req = request.get_json()
    print(req)
    sub = req["subject"]
    obj = req["object"]
    act = req["action"]

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
    app.run(host='0.0.0.0')

