import json
import time

import requests

from flask import Flask, request

import casbin

import PolicyMethods
import RSAMethods
import AnalyticMethods

app = Flask(__name__)

""" 
    Return Policy Rules:
        1: Successful Request
        2: Failed Due To Being Unable To Read Request
        3: Failed Due To Incorrect Of Credentials 
        4: Failed Due To Access Control
        5: Failed Due To Specific Condition (Request Already Exists, etc)
        6: Unknown Error
        Other: Content Requested
"""


@app.route('/request_item_list', methods=['GET'])
def request_devices():
    """ This method will allow users to get the list of devices on startup. I am unsure if I will add specific rules for
     this"""
    r = requests.get("http://localhost:8080/rest/items?recursive=false")
    raw_items = json.loads(r.text)
    items = []
    for item in raw_items:
        items.append(item["name"])

    # message = RSAMethods.encrypt_rsa(items)
    # return message
    add_request_data("Item_Request", "List_of_Devices", "1", "NULL", time.time())
    return json.dumps(items)


@app.route('/request_item_options', methods=['GET'])
def request_devices2():
    """ This method will allow users to get the list of devices on startup. I am unsure if I will add specific rules for
     this"""
    """TODO ping jemma here and return devices"""

    value = request.form["key"]
    r = requests.get("http://localhost:8080/rest/items/" + str(value))
    raw_items = json.loads(r.text)
    items = raw_items["type"]
    print(items)
    # message = RSAMethods.encrypt_rsa(items)
    # return message
    add_request_data("Item_Request", "List_of_Item_Options", "1", "NULL", time.time())
    return json.dumps(items)


@app.route('/update_item_state', methods=['POST'])
def request_access():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    try:
        input = RSAMethods.decrypt(request.get_data())
        print(input)
        req = json.loads(input)
        print(req)
    except:
        print("ERROR: Request was not parsed from JSON")
        add_request_data("Item_Request", "Update_Item_State", "2", "Not_Correctly_Encrypted", time.time())
        return "2"
    try:
        val = req["key"]
        opt = req["option"]
        sub = req["subject"]
        obj = req["object"]
        act = req["action"]
    except:
        add_request_data("Item_Request", "Update_Item_State", "3", "Lacking_Policy_Credentials", time.time())
        print("ERROR: Policy Credentials not found")
        return "3"

    # Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)
    print("Enforcement Point")
    if obj == "items":
        print("Is Object")
        e = casbin.Enforcer("acl.conf", "policies.csv")

        if e.enforce(sub, obj, act):
            print("Successful Access")
            print(val)
            print(str(opt).upper())
            r = requests.post("http://localhost:8080/rest/items/" + str(val), data=str(opt).upper())
            print(r.text)
            # r = requests.put("http://localhost:8080/rest/items/" + str(val) + "/state", data=str(opt).upper())
            add_request_data("Item_Request", "Update_Item_State", "1", "NULL", time.time())
            print("Item Option Updated")
            return "1"
        else:
            add_request_data("Item_Request", "Update_Item_State", "4", "Insufficient_Access_Credentials", time.time())
            # deny the request, show an error
            print("Request Denied Due To Lack Of Permissions")
            return "4"
    else:
        return "3"

    return "6"


@app.route('/request_policies_with_item_access')
def request_policies():
    add_request_data("Policy_Request", "Get_Valid_Policies_For_Items", "1", "NULL", time.time())
    return json.dumps(PolicyMethods.get_valid_users())


@app.route('/request_all_policies')
def request_policies1():
    add_request_data("Policy_Request", "Get_All_Policies", "1", "NULL", time.time())
    return json.dumps(PolicyMethods.get_list())


@app.route('/update_policies', methods=['POST'])
def update_policies():
    """This is where the user will attempt to make specific access requests and will have to face ABAC """
    # ciphertext = request.form["d"]
    # size = request.form["s"]
    try:
        input = RSAMethods.decrypt(request.get_data())
        print(input)
        req = json.loads(input)
        print(req)
    except:
        add_request_data("Policy_Request", "Update_Policies", "2", "Not_Correctly_Encrypted", time.time())
        print("ERROR: Request was not parsed from JSON")
        return "2"
    try:
        sub = req["subject"]
        obj = req["object"]
        act = req["action"]
    except:
        add_request_data("Policy_Request", "Update_Policies", "3", "Lacking_Policy_Credentials", time.time())
        print("ERROR: Policy Credentials not found")
        return "3"

    # Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)

    if obj == "policies":
        e = casbin.Enforcer("acl.conf", "policies.csv")

        if e.enforce(sub, obj, act):
            print("Sufficient Policies")
            if act == "add":
                print("Add Action")
                new_string = "p, " + req["new"]
                if PolicyMethods.find_row(new_string):
                    print("Policy Already Exists")
                    add_request_data("Policy_Request", "Add_Policy", "Unsure", "Policy_Already_Exists", time.time())
                    return "5"
                else:
                    print("New Policy Added")
                    PolicyMethods.add_policy(new_string)
                    add_request_data("Policy_Request", "Add_Policy", "1", "NULL", time.time())
                    return "1"
            elif act == "edit":
                print("Edit Action")
                old_policy = "p, " + req["old"]
                new_policy = "p, " + req["new"]
                print(old_policy + " old policy")
                print(req["old"] + " raq policy")
                if PolicyMethods.find_row(old_policy):
                    print("Found row")
                    add_request_data("Policy_Request", "Edit_Policy", "1", "NULL", time.time())
                    PolicyMethods.edit_policy(old_policy, new_policy)
                    return "1"
                else:
                    print("Did not find row")
                    add_request_data("Policy_Request", "Edit_Policy", "Unsure", "Policy_Does_Not_Exist", time.time())
                    resp = "The policy requested doesnt exist"
                    return "5"
            elif act == "del":
                print("Delete Action")
                policy_to_delete = "p, " + req["old"]  # Should read "sub,obj,act"
                if PolicyMethods.find_row(policy_to_delete):
                    add_request_data("Policy_Request", "Delete_Policy", "1", "NULL", time.time())
                    PolicyMethods.delete_policy(policy_to_delete)
                    return "1"
                else:
                    add_request_data("Policy_Request", "Delete_Policy", "Unsure", "Policy_Does_Not_Exist", time.time())
                    return "5"

        else:
            # deny the request, show an error
            add_request_data("Policy_Request", "Update_Policies", "4", "Insufficient_Access_Credentials", time.time())
            print("Insufficient Policies")
            resp = "You do not have the valid permissions to access devices"
            return "4"
    else:
        return "3"

    return "6"


@app.route('/request_analytics', methods=['POST'])
def request_analytics():
    try:
        input = RSAMethods.decrypt(request.get_data())
        print(input)
        req = json.loads(input)
        print(req)
    except:
        add_request_data("Analytics_Request", "Request_Analytics", "2", "Not_Correctly_Encrypted", time.time())
        print("ERROR: Request was not parsed from JSON")
        return "2"
    try:
        sub = req["subject"]
        obj = req["object"]
        act = req["action"]
    except:
        add_request_data("Analytics_Request", "Request_Analytics", "3", "Lacking_Policy_Credentials", time.time())
        print("ERROR: Policy Credentials not found")
        return "3"

    # Leave commented for now until the final show, then the thing should decrypt and the
    # message = methods.decrypt_RSA(ciphertext)

    if obj == "analytics":
        e = casbin.Enforcer("acl.conf", "policies.csv")

        if e.enforce(sub, obj, act):
            choice = req["type"]
            if choice == 1:
                add_request_data("Analytics_Request", "Request_Analytics", "1", "NULL", time.time())
                return json.dumps(AnalyticMethods.get_all_request_data())
            elif choice == 2:
                add_request_data("Analytics_Request", "Request_Analytics", "1", "NULL", time.time())
                return json.dumps(AnalyticMethods.get_all_successful_request_data())
            elif choice == 3:
                add_request_data("Analytics_Request", "Request_Analytics", "1", "NULL", time.time())
                return json.dumps(AnalyticMethods.get_all_unsuccessful_request_data())
            else:
                add_request_data("Analytics_Request", "Request_Analytics", "5", "Request_Type_Unavailable",
                                 time.time())
                return 5


@app.route('/receive_feedback', methods=['POST'])
def receive_feedback():
    try:
        input = RSAMethods.decrypt(request.get_data())
        print(input)
        req = json.loads(input)
        print(req)
    except:
        add_request_data("Feedback_Request", "Receive_Feedback", "2", "Not_Correctly_Encrypted", time.time())
        print("ERROR: Request was not parsed from JSON")
        return "2"
    try:
        email = req["email"]
        subject = req["sub"]
        feedback = req["feed"]
    except:
        add_request_data("Feedback_Request", "Receive_Feedback", "3", "Lacking_Policy_Credentials", time.time())
        print("ERROR: Policy Credentials not found")
        return "3"

    with open('feedback.csv', 'a') as csv_file:
        # policy_writer = csv.writer(csv_file)
        csv_file.writelines(email + "," + subject + "," + feedback + "\n")
    add_request_data("Feedback_Request", "Receive_Feedback", "1", "NULL", time.time())
    return "1"


def add_request_data(request_type, resource_requested, response, reason, timestamp):
    with open('RequestData.csv', 'a') as csv_file:
        # policy_writer = csv.writer(csv_file)
        csv_file.writelines(request_type + "," + resource_requested + "," + response + "," + reason + "," +
                            str(timestamp) + "\n")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
