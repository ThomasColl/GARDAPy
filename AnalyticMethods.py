import csv


def get_all_request_data():
    x_list = []
    y_list = []
    with open('RequestData.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            x_list.append(row[4])
            y_list.append(row[2])
    csv_file.close()

    return x_list, y_list


def get_successful_request_data():
    x_list = []
    y_list = []
    with open('RequestData.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            if row[2] == "1":
                x_list.append(row[4])
                y_list.append(row[2])
    csv_file.close()

    return x_list, y_list


def get_unsuccessful_request_data():
    x_list = []
    y_list = []
    with open('RequestData.csv', 'r+') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            if row[2] != "1":
                x_list.append(row[4])
                y_list.append(row[2])
    csv_file.close()

    return x_list, y_list
