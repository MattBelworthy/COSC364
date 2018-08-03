"""
@file: RIPdaemon.py
@author: Logan Beard, Matt Belworthy
@description: The main script for the RIP daemon
"""

from configParser import *
import socket
import select
import queue
import time
import random

LOCAL_HOST = "127.0.0.1"

# TIMER VARIABLES
update_sleep = 30  # default: 30
timeout_sleep = 180  # default: 180
garbage_sleep = 120  # default: 120
time_between_output = 5  # time in seconds between each output of routing table

# LINK DATA (LOCAL ROUTING TABLE)
link_data = []


""" =========================== PACKET FUNCTIONS =============================== """


def create_packet_header(self_id):
    """Creates the common header for the RIP packet"""
    command = 2
    version = 2

    command = command.to_bytes(1, byteorder='big', signed=False)
    version = version.to_bytes(1, byteorder='big', signed=False)
    router_id = int(self_id).to_bytes(2, byteorder='big', signed=False)

    header = command + version + router_id

    return header


def create_rip_entry(destination, metric):
    """Creates a single entry to be stuffed into the RIP packet"""
    afi = 2
    zero = 0

    afi = afi.to_bytes(2, byteorder='big', signed=False)
    zeroes1 = zero.to_bytes(2, byteorder='big', signed=False)
    destination = destination.to_bytes(4, byteorder='big', signed=False)
    zeroes2 = zero.to_bytes(8, byteorder='big', signed=False)
    metric = metric.to_bytes(4, byteorder='big', signed=False)

    entry = afi + zeroes1 + destination + zeroes2 + metric

    return entry

def form_rip_packet(self_id, neighbours, only_changes):
    """Combines the common header and routing table entries into a whole RIP packet in bytes"""

    neighbour_ids = neighbours.keys()
    messages = {}

    for neighbour in neighbour_ids:

        header = create_packet_header(self_id)
        packet = header

        for link in link_data:
            if link[0] != self_id:
                router_id = link[1]["router_id"]
                metric = link[1]["metric"]
                next_hop = link[1]["next_hop_id"]
                route_change = link[1]["route_change"]
                entry = None

                if only_changes:
                    if route_change:
                        if next_hop == neighbour and router_id != neighbour:
                            entry = create_rip_entry(router_id, 16)
                        else:
                            entry = create_rip_entry(router_id, metric)
                else:
                    if next_hop == neighbour and router_id != neighbour:
                        # print("sending 16 to {} for destination {}".format(neighbour, router_id))
                        entry = create_rip_entry(router_id, 16)
                    else:
                        entry = create_rip_entry(router_id, metric)

                if entry:
                    packet += entry

        messages[neighbour] = packet

    return messages


def parse_rip_packet(packet, self_id, sender_port, neighbours):
    """Pulls routing information out of incoming RIP packet and passes to distance vector function"""
    sender = int(packet[2] + packet[3])
    number_of_entries = int((len(packet) - 4) / 20)

    add_neighbour_entry(sender, sender_port, neighbours)

    entries = packet[4:]
    for i in range(0, number_of_entries):
        entry = entries[(i*20):((i+1)*20)]
        destination = int(entry[4] + entry[5] + entry[6] + entry[7])
        metric = int(entry[16] + entry[17] + entry[18] + entry[19])
        #print("Sender {} says: Destination: {}, Metric: {}".format(sender, destination, metric))

        refresh_timeout(sender)
        if destination != int(self_id):
            distance_vector(sender_port, sender, destination, metric)


def packet_consistency_check(packet):
    """Checks static RIP packet fields, and metric values in incoming packet, returns True if
    packet is sanitary, False if not - meaning it will be dropped"""
    valid = True
    number_of_entries = int((len(packet) - 4) / 20)

    command = int(packet[0])
    version = int(packet[1])

    entries = packet[4:]
    for i in range(0, number_of_entries):
        entry = entries[(i * 20):((i + 1) * 20)]
        metric = int(entry[16] + entry[17] + entry[18] + entry[19])
        if metric < 0 or metric > 16:
            valid = False

    if command != 2:
        valid = False

    if version != 2:
        valid = False

    return valid


""" ============================================================================ """
""" ============================================================================ """


""" =========================== TIMER FUNCTIONS ================================ """


def refresh_timeout(router_id):
    """Updates an entry in the local routing table"""
    for link in link_data:
        if link[0] == router_id:
            link[1]["timeout"] = time.time() + timeout_sleep
            link[1]["garbage"] = None
    return


def check_timeouts():
    """Checks to see if timeout has expired"""
    for link in link_data:
        if link[1]["timeout"]:
            if link[1]["timeout"] - time.time() <= 0:
                link[1]["metric"] = 16
                link[1]["route_change"] = True
                link[1]["timeout"] = None
                link[1]["garbage"] = time.time() + garbage_sleep
    return


def reset_update_timer():
    """Sets the next update time to 30 seconds +/- 0.5 sec"""
    offset = random.randint(-50, 50) / 100
    next_update = time.time() + (update_sleep + offset)

    return next_update


def periodic_update_needed(next_update):
    """Check to see if it is time to send periodic update"""
    if time.time() >= next_update:
        return True
    else:
        return False


def triggered_update_needed():
    """Check to see if triggered update is necessary"""
    for link in link_data:
        if link[1]["route_change"]:
            return True

    return False


def reset_triggered_backoff():
    """Generate a new random backoff time between 1 and 5 seconds"""
    backoff = random.randint(100, 500) / 100
    new_backoff = time.time() + backoff
    return new_backoff


def is_time_to_output(next_output):
    """Polls time to see if output is needed"""
    if time.time() > next_output:
        return True

    return False


def reset_output_timer(interval):
    """Sets the next output time"""
    new_time = time.time() + interval
    return new_time


""" ============================================================================ """
""" ============================================================================ """


""" ======================= ROUTING TABLE FUNCTIONS ============================ """


def distance_vector(origin_port, origin, destination, metric):
    """Calculates if incoming route info is preferred over current table entry"""
    origin_link_entry = get_entry(origin)
    destination_link_entry = get_entry(destination)

    # compute the total distance to the destination as the metric received plus the distance to the sender
    dist_to_origin = origin_link_entry["metric"]
    total_dist = dist_to_origin + metric
    trusted = False

    # if the information about the destination came from the next router along the path to that destination we are
    # inclined to believe that information for better or worse as per split horizon
    if destination_link_entry:
        if destination_link_entry["next_hop_id"] == origin:
            trusted = True

    # mark route as unreachable if a trusted router says so
    if total_dist >= 16 and trusted:
        update_table_entry(destination, 16, origin_port, origin, change=True)

    elif total_dist < 16:
        if destination_link_entry:
            current_dist_to_destination = destination_link_entry["metric"]
            # if the information comes from an untrusted router only update if the metric is lower
            if not trusted:
                if total_dist < current_dist_to_destination:
                    update_table_entry(destination, total_dist, origin_port, origin, change=True)

            # if the information comes from a trusted router update regardless of metric
            else:
                if total_dist != current_dist_to_destination:
                    update_table_entry(destination, total_dist, origin_port, origin, change=True)
                else:
                    update_table_entry(destination, total_dist, origin_port, origin, change=False)
        else:
            # if there is no current entry for that destination - add it to our routing table
            create_table_entry(destination, total_dist, origin_port, origin)


def init_own_link(self_id):
    """Adds own link to routing table (wont be printed) for reference purposes"""
    data = {
        "router_id": self_id,
        "metric": None,
        "next_hop": None,
        "next_hop_id": None,
        "route_change": None,
        "timeout": None,
        "garbage": None
    }

    link_data.append([self_id, data])

    return


def init_neighbour_data(links):
    """Takes the data supplied in the cfg file output ports and creates entries
    in the link_data table"""
    neighbour_metrics = {}
    neighbour_ports = {}


    for link in links:
        link = link.split('-')
        port = int(link[0])
        metric = int(link[1])
        router_id = int(link[2])
        neighbour_metrics[router_id] = metric
        neighbour_ports[router_id] = port


    return [neighbour_metrics, neighbour_ports]


def add_neighbour_entry(router_id, port, neighbours):
    """Adds route to routing table as per usual but has ability to look up neighbour metrics
    given in config file for the sake of initialising (otherwise there is no way of deriving the metric)"""
    if check_entry_exists(router_id):
        metric = neighbours[router_id]
        current_entry = get_entry(router_id)
        if metric < current_entry["metric"]:
            update_table_entry(router_id, metric, port, router_id, change=True)
    else:
        metric = neighbours[router_id]
        create_table_entry(router_id, metric, port, router_id)


def create_table_entry(router_id, metric, next_hop, next_hop_id):
    """Creates an entry in the local routing table"""
    data = {
        "router_id": router_id,
        "metric": metric,
        "next_hop": next_hop,
        "next_hop_id": next_hop_id,
        "route_change": False,
        "timeout": time.time() + timeout_sleep,
        "garbage": None
    }

    link_data.append([router_id, data])

    return


def update_table_entry(router_id, metric, next_hop, next_hop_id, change):
    """Updates an entry in the local routing table"""
    for link in link_data:
        if link[0] == router_id:
            if metric == 16:
                new_data = {
                    "router_id": router_id,
                    "metric": metric,
                    "next_hop": next_hop,
                    "next_hop_id": next_hop_id,
                    "route_change": change,
                    "timeout": None,
                    "garbage": time.time() + garbage_sleep
                }
            else:
                new_data = {
                    "router_id": router_id,
                    "metric": metric,
                    "next_hop": next_hop,
                    "next_hop_id": next_hop_id,
                    "route_change": change,
                    "timeout": time.time() + timeout_sleep,
                    "garbage": None
                }
            link[1] = new_data
    return


def get_entry(router_id):
    """Returns entry in table with given router id"""
    for link in link_data:
        if link[0] == router_id:
            return link[1]

    return None


def get_entry_index(router_id):
    """Gets the index number of a specific destination's entry in the routing table"""
    for i in range(0, len(link_data)):
        if link_data[i][0] == router_id:
            return i

    return None


def check_entry_exists(router_id):
    """Checks if entry already exists"""
    for link in link_data:
        if link[0] == router_id:
            return True

    return False


def reset_route_change_flags():
    """Resets route change flags to false after triggered update sendt"""
    for i in range(1, len(link_data)):
        link_data[i][1]["route_change"] = False


def check_garbage():
    """Checks to see if timeout has expired"""
    for link in link_data:
        if link[1]["garbage"]:
            if link[1]["garbage"] - time.time() <= 0:
                index = get_entry_index(link[0])
                del(link_data[index])
    return


def output_link_data(start_time, self_id):
    """Prints link data table nicely"""
    #print("\nROUTING TABLE FOR ROUTER " + self_id + "  (" + str(int(time.time() - start_time)) + " sec after start):")
    print("\nROUTING TABLE FOR ROUTER " + self_id)
    '''print("------------------------------------------------------------------------------------\n" +
          "| DESTINATION | METRIC | NEXT HOP | ROUTE CHANGE | TIMEOUT IN | GARBAGE COLLECT IN |\n" +
          "|-------------|--------|----------|--------------|------------|--------------------|")'''
    print("-----------------------------------\n" +
          "| DESTINATION | METRIC | NEXT HOP |\n" +
          "|-------------|--------|----------|")
    for link in link_data:
        link = link[1]
        if link["router_id"] != self_id:
            if not link["timeout"]:
                to_sec = "-"
            else:
                to_sec = int(link["timeout"] - time.time())
            if not link["garbage"]:
                gb_sec = "-"
            else:
                gb_sec = int(link["garbage"] - time.time())

            print("|{0:^13}|{1:^8}|{2:^10}|{3:^14}|{4:>5} sec   |{5:>10} sec      |".format(link["router_id"],
                                                                                            link["metric"],
                                                                                            link["next_hop_id"],
                                                                                            str(link["route_change"]),
                                                                                            str(to_sec),
                                                                                            gb_sec))
            '''print("|{0:^13}|{1:^8}|{2:^10}|".format(link["router_id"], link["metric"], link["next_hop_id"]))'''

    #print("------------------------------------------------------------------------------------")
    print("-----------------------------------")

    return


""" ============================================================================ """
""" ============================================================================ """


""" ======================= INITIALISATION FUNCTIONS =========================== """


def get_config_values():
    """Use the modules in configParser to retrieve initialisation values from .cfg file,
    returns value dict if it is read OK"""
    cfg_name = get_config_name()
    cfg_values = parse_config_file(cfg_name)
    missing_params = check_missing_parameters(cfg_values)
    if missing_params:
        print_missing_parameters(missing_params)
    else:
        if check_config_values(cfg_values):
            return cfg_values


def bind_sockets(ports):
    """Takes the list of input ports and binds a socket to each"""
    sockets = []
    output = ">> Sockets bound on ports: "
    if ports:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", int(port)))
            sockets.append(sock)
            output += str(port + " ")

    print(output)
    return sockets


""" ============================================================================ """
""" ============================================================================ """


def event_loop(router_id, outputs, sockets):
    """Main loop of the RIP daemon - uses select() to atomically handle receiving, sending and processing
    functionality"""

    # initialise timers
    next_update = reset_update_timer()
    next_output = reset_output_timer(time_between_output)
    next_backoff = 0
    start_time = time.time()

    # add own link to routing table, and create dictionary with neighbours metrics
    init_own_link(router_id)
    neighbour_info = init_neighbour_data(outputs)
    nbr_metrics, nbr_ports = neighbour_info[0], neighbour_info[1]
    output_link_data(start_time, router_id)

    # initialise message queues, designate socket to send packets out from
    message_queues = {}
    out_socket = [sockets[0]]

    # enter select() loop indefinitely
    while True:
        readable, writable, exceptional = select.select(sockets, out_socket, sockets)

        # ----------- READ MESSAGES -------------- #

        for s in readable:

            try:
                d = s.recvfrom(1024)
                data = d[0]
                addr = d[1]
                message_queues[addr[1]] = queue.Queue()
            except ConnectionResetError:
                continue

            if data:
                message_queues[addr[1]].put(data)

        # ----------- SEND MESSAGES -------------- #

        outgoing_socket = writable[0]

        packets = None
        # check to see if it is necessary to send a periodic update
        if periodic_update_needed(next_update):
            next_update = reset_update_timer()
            packets = form_rip_packet(router_id, nbr_metrics, only_changes=False)

        # check to see if it is necessary to send a triggered update
        elif triggered_update_needed():
            if time.time() >= next_backoff:
                output_link_data(start_time, router_id)
                next_output = reset_output_timer(time_between_output)
                packets = form_rip_packet(router_id, nbr_metrics, only_changes=True)
                reset_route_change_flags()
                next_backoff = reset_triggered_backoff()

        # if there's something to send - send it
        if packets:
            for neighbour in nbr_ports.keys():
                if packets[neighbour]:
                    outgoing_socket.sendto(packets[neighbour], (LOCAL_HOST, nbr_ports[neighbour]))

        # ----------- PROCESS MESSAGES -------------- #

        # for each message in each message queue check for consistency then parse if it is clean, drop if not
        for key in message_queues.keys():
            try:
                q = message_queues[key]
                while not q.empty():
                    sender_port = int(key)
                    message = q.get_nowait()
                    if packet_consistency_check(message):
                        parse_rip_packet(message, router_id, sender_port, nbr_metrics)

            except KeyError:
                continue

        # check to see if any routes need to be timed out/deleted
        check_timeouts()
        check_garbage()

        # poll to see if enough time has elapsed before printing the routing table to the screen
        if is_time_to_output(next_output):
            output_link_data(start_time, router_id)
            next_output = reset_output_timer(time_between_output)


def main():
    """Initialisation steps"""
    # Get the config values
    init_values = get_config_values()

    # Parse the dictionary into list variables
    router_id = init_values['router-id'][0]
    input_ports = init_values['input-ports']
    outputs = init_values['outputs']

    # Bind the input ports as UDP sockets
    sockets = bind_sockets(input_ports)

    # Enter main loop to handle RIP daemon functions
    event_loop(router_id, outputs, sockets)


main()
