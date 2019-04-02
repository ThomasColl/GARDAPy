import csv
import fileinput
from os import fdopen, remove
from shutil import move
from tempfile import mkstemp


def find_row(new_policy):
    with open('policies.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        policy_exists = False
        for row in csv_reader:
            row_as_string = ",".join(row)
            if new_policy == row_as_string:
                return row_as_string
    csv_file.close()
    return False


def add_policy(new_policy):
    with open('policies.csv', 'a') as csv_file:
        policy_writer = csv.writer(csv_file)
        csv_file.writelines(new_policy + "\n")


def edit_policy(old_policy, new_policy):
    # Create temp file
    fh, abs_path = mkstemp()
    with fdopen(fh, 'w') as new_file:
        with open('policies.csv') as old_file:
            for line in old_file:
                new_file.write(line.replace(old_policy, new_policy))
    # Remove original file
    remove('policies.csv')
    # Move new file
    move(abs_path, 'policies.csv')


def delete_policy(policy_to_delete):
    fh, abs_path = mkstemp()
    with fdopen(fh, 'w') as new_file:
        with open('policies.csv') as old_file:
            for line in old_file:
                new_file.write(line.replace(policy_to_delete, ""))
    # Remove original file
    remove('policies.csv')
    # Move new file
    move(abs_path, 'policies.csv')


def get_valid_users():
    with open('policies.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        users = []
        for row in csv_reader:
            if row:
                if "items" in row[2]:
                    users.append(row[1])
    csv_file.close()
    return users


def get_list():
    with open('policies.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        policy = []
        for row in csv_reader:
            if row:
                policy.append(row[1] + "," + row[2] + "," + row[3])
    csv_file.close()

    return policy

