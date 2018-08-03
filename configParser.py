"""
@file: configParser.py
@author: Logan Beard, Matt Belworthy
@description: Functions to handle the parsing of the .cfg file on startup of daemon
"""

import re
import os.path

empty_field_exception = ">> Error: config file value field cannot be empty for "


def get_config_name():
    """Asks for config filename (with sanitary checks)"""
    while True:
        filename = input(">> Configuration file name: ")
        if re.match(".+.cfg", filename):
            if os.path.isfile("./"+filename):
                return filename
            else:
                print(">> Error: file does not exist in current directory")
                continue
        else:
            print(">> Error: filename not valid. Use format 'name.cfg'")
            continue


def parse_config_file(filename):
    """Reads config file and returns pairs of variables and their values as dictionary"""
    pairs = {}
    file = open(filename, "r")

    for line in file:
        line_data = line.strip("\n")
        line_data = line_data.replace(" ","")
        if re.match(".+:.*", line_data):
            variable, value = line_data.split(":")
            if re.match("[\S]+", value):
                value_container = [value]
                if re.search(",", value):
                    values = value.split(",")
                    pairs[variable] = values
                else:
                    pairs[variable] = value_container
            else:
                value_container = ['NULL']
                pairs[variable] = value_container

    return pairs


def check_missing_parameters(parameter_dict):
    """Checks the config params to see if the necessary ones are present, returns a list of missing ones"""
    expected = {'router-id': False,
                'input-ports': False,
                'outputs': False}
    parameters = parameter_dict.keys()

    for par in parameters:
        if par in expected.keys():
            expected[par] = True

    missing = []
    necessary_pars = expected.keys()
    for par in necessary_pars:
        if expected[par] == False:
            missing.append(par)

    return missing


def print_missing_parameters(parameters):
    """Prints the missing parameters to the console"""
    out_string = ">> Error: config file is missing parameters "
    for i in range(0, len(parameters)):
        out_string += "'" + parameters[i] + "'"
        if i + 1 < len(parameters):
            out_string += ", "
        else:
            out_string += "."

    print(out_string)


def check_router_id_value(parameter_dict):
    """Sanitary checks for the router-id field values"""
    router_id_exception = ">> Error: router-id must be a number between 1 and 64000"
    try:
        router_id = parameter_dict['router-id']
        if router_id[0] == 'NULL':
            print(empty_field_exception + 'router_id')
            return False
    except KeyError:
        print(empty_field_exception + 'router-id')
        return False

    router_id = router_id[0]

    if router_id.isdigit():
        if 1 <= int(router_id) <= 64000:
            return True
        else:
            print(router_id_exception)
    else:
        print(router_id_exception)

    return False


def check_input_port_values(parameter_dict):
    """Sanitary checks for the input-port field values"""
    inputs_exception = "Input-port(s) must be a number between 1024 and 64000"
    try:
        input_ports = parameter_dict['input-ports']
        if input_ports[0] == 'NULL':
            print(empty_field_exception + 'input_ports')
            return False
    except KeyError:
        print(empty_field_exception + 'input_ports')
        return False

    all_ports_correct_format = True
    for port in input_ports:
        try:
            port = int(port)
            if 1024 <= port <= 64000:
                continue
            else:
                all_ports_correct_format = False
                print(">> Error: Invalid input-port value: " + str(port))
        except ValueError:
            all_ports_correct_format = False
            print(">> Error: Invalid input-port value syntax: '" + str(port) + "'")

    if not all_ports_correct_format:
        print(10 * " " + inputs_exception)
        return False
    else:
        return True


def check_output_values(parameter_dict):
    """Sanitary checks for the outputs field values"""
    try:
        outputs = parameter_dict['outputs']
        if outputs[0] == 'NULL':
            print(empty_field_exception + 'outputs')
            return False
    except KeyError:
        print(empty_field_exception + "outputs")
        return False

    outputs_exception = 10 * " " + "Outputs must be in the form '<1-64000>-<0-16>-<1024-64000>' e.g. '5000-1-2'"

    all_ports_correct_format = True
    for port in outputs:
        correct_format = False
        numbers = port.split("-")
        if len(numbers) == 3:
            try:
                if 1024 <= int(numbers[0]) <= 64000:
                    if 0 <= int(numbers[1]) <= 16:
                        if 1 <= int(numbers[2]) <= 64000:
                            correct_format = True
            except ValueError:
                all_ports_correct_format = False
        else:
            all_ports_correct_format = False

        if not correct_format:
            print(">> Error: Invalid output value syntax: '" + port + "'")
            all_ports_correct_format = False

    if not all_ports_correct_format:
        print(outputs_exception)
        return False
    else:
        return True


def check_config_values(parameter_dict):
    """Checks that the values of config parameters are of right type and format"""
    checklist = {'router-id': check_router_id_value(parameter_dict),
                 'input-ports': check_input_port_values(parameter_dict),
                 'outputs': check_output_values(parameter_dict)}

    check_results = checklist.values()
    result = True
    for check in check_results:
        if not check:
            result = False
    if not result:
        print("\n>>>> One or more config file errors has been detected - exiting.")
    else:
        print("\n>> Configuration accepted.\n")

    return result
