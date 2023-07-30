import platform
import pyshark
import psutil
import shutil
import re
from cover import cover

global INTERFACE
global FILTER
global MY_IP
BUFFER_PACKETS = None


def get_str(): 
    """
    This function takes user input from the console and returns the input as a string.

    Returns:
        str: The user input as a string.
    """
    while True:
        name = input()
        if name.strip():
            return name
        else:
            print("Error: Empty Name")


def get_and_validate_option(max_option):
    """
    This function validates if the value entered by the user is valid
    (being an integer and within the range of options). 
    It takes the maximum value of the option range as input and returns
    the valid integer entered by the user.

    Args:
        max_option (int): Maximum number of the option range.
    Returns:
        int: Valid integer entered by the user.
    """
    while True:
        try:
            option = int(input())
            if check_range(option,max_option):
                return option
            else:
                print("Please, select a correct option.")
        except ValueError:
            print("Please, enter the correct data type (int).")


def get_os():
    """
    Returns the name of the operating system on which the program is running.

    Returns:
        str: The name of the operating system ('Windows', 'macOS', or 'Linux').
    """
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Darwin":
        return "macOS"
    else:
        return "Linux"


def get_interfaces():
    """
    This function lists all available network interfaces and prompts the user to select one.
    It also identifies the IP address of the selected interface and stores it in the global variable MY_IP.

    The selected interface name is stored in the global variable INTERFACE.

    Returns:
        None
    """
    interfaces = psutil.net_if_addrs()
    interfaces_dic = {}
    global INTERFACE
    global MY_IP
    global FILTER
    FILTER = ""
    print("")
    print("Select a interface:")
    print("")
    for i, interface_name in enumerate(interfaces.keys(), start=1):
        interfaces_dic[i] = interface_name
        print("{} - {}".format(i, interfaces_dic[i]))
    print("")
    interface_selected=get_and_validate_option(i)

    print("The selected interface is: {}".format(interfaces_dic[interface_selected]))

    INTERFACE = interfaces_dic[interface_selected]

    interface_selected = interfaces[INTERFACE]

    for address_obj in interface_selected:
        if detect_ip_format(address_obj.address):
            MY_IP = address_obj.address
            print("ip address: {}".format(MY_IP))


def detect_ip_format(value):
    """
    This function checks if the given value has the format of an IP address.
    Args:
        value (str): The value to be checked.

    Returns:
        bool: True if the value has the format of an IP address, False otherwise.
    """    
    pattern = r'^(\d+\.)+\d+$'
    if re.match(pattern, value):
        return True
    else:
        return False

def check_range(option, max_range):
    """
    This function validates if the received integer is within the range
    of options (between 1 and the specified maximum).

    Returns:
        True or False
    """
    return 1 <= option <= max_range


def import_pcap_file():
    """
    This function prompts the user to input the path of a .pcap file to import.
    The function then attempts to copy the file to the "./data/" location with
    the name of trace.pcap

    Returns:
        None
    """
    print("")
    print("Specify the path of the .pcap file to import")
    origen = get_str()
    print("The path is: {}".format(origen))
    try:
        shutil.copy(origen, f"./data/trace.pcap")
        print("File copied successfully.")
    except FileNotFoundError:
        print("The source file does not exist.")
    except IsADirectoryError:
        print("The destination path is not valid.")


def show_filter():
    """
    This function displays the currently applied filter.
    If there is no active filter, it prints a message indicating that there is no active filter.

    Returns:
        None
    """
    global FILTER
    if FILTER == "":
        print("There is no active filter.")
    else:
        print("The applied filter is: {}".format(FILTER))
        print("")


def set_filter_my_ip_src():
    """
    This function sets the filter to capture packets with the source IP address equal to MY_IP.

    Returns:
        None
    """
    global MY_IP
    global FILTER
    FILTER = "ip src " + str(MY_IP)


def set_filter_my_ip_dst():
    """
    This function sets the filter to capture packets with the destination IP address equal to MY_IP.

    Returns:
        None
    """
    global MY_IP
    global FILTER
    FILTER = "ip dst " + str(MY_IP)


def set_filter_ip_dst():
    """
    This function sets the filter to capture packets with the destination IP address specified by the user.

    Returns:
        None
    """
    global FILTER
    while True:
        print("")
        print("Write the ip address:")
        ip = input()
        if ip.strip():
            break
        else:
            print("Write the ip address:")
    FILTER = "ip dst " + str(ip)


def common_filters():
    """
    This function displays some common filters and allows the user to select a filter option.

    Returns:
        None
    """
    global FILTER
    global MY_IP
    print("1 - HTTP and HTTPS") # http or ssl 80 and 443
    print("2 - Filter by my source IP: {}".format(MY_IP))
    print("3 - Filter by my destination IP: {}".format(MY_IP))
    print("4 - Filter by destination IP")
    print("5 - Filter SSH traffic") # 22
    print("6 - Filter Telnet traffic") # 23
    print("")
    print("7 - Back")

    option=get_and_validate_option(7)

    if option == 7:
        print("")
    elif option == 1:
        FILTER = "tcp port 80 or tcp port 443"
    elif option == 2:
        set_filter_my_ip_src()
    elif option == 3:
        set_filter_my_ip_dst()
    elif option == 4:
        set_filter_ip_dst()
    elif option == 5:
        FILTER = "tcp port 22"
    elif option == 6:
        FILTER = "tcp port 23"


def manual_filter():
    """
    This function allows the user to manually input a filter syntax and stores it in the global variable FILTER.

    Returns:
        None
    """
    global FILTER
    while True:
        print("")
        print("Write the correct syntax for the filter:")
        manual_filter = input()
        if manual_filter.strip():
            break
        else:
            print("Write the correct syntax for the filter:")
    FILTER = manual_filter


def erase_filter():
    """
    This function clears the applied filter by resetting the global FILTER variable to an empty string.

    Returns:
        None
    """
    global FILTER
    FILTER = ""


def menu_filters():
    """
    This function displays a menu to the user, providing options to list filters, apply a manual filter,
    or go back to the previous menu. Depending on the user's selection, it calls the appropriate functions for further action.

    Returns:
        None
    """
    while True:
        print("1 - List the most common filters")
        print("2 - Apply a manual filter")
        print("")
        print("3 - Back")

        option=get_and_validate_option(3)

        if option == 1:
            common_filters()
            break
        elif option == 2:
            manual_filter()
            break
        elif option == 3:
            break


def capture_traffic():
    """
    This function captures network packets for the selected interface and applies the current filter (if any).
    The captured packets are stored in the global variable BUFFER_PACKETS.

    The user is prompted to specify the number of packets to capture.

    Returns:
        None
    """
    global BUFFER_PACKETS
    BUFFER_PACKETS = {}
    print("How many network packets do you want to capture?")
    while True:
        try:
            number_packets = int(input())
            break
        except ValueError:
            print("Please, enter the correct data type (int).")
    print("Traffic will be captured for the interface: {}, applying the filter: {}".format(INTERFACE, FILTER))
    capture = pyshark.LiveCapture(interface=INTERFACE, bpf_filter=FILTER)

    for i, packet in enumerate(capture.sniff_continuously(number_packets), start=1):

        print(i)
        print(packet)
        print('-' * 50)
        BUFFER_PACKETS[i] = packet


def menu_capture_and_filters():
    """
    This function displays a menu for capturing and filtering packets. It allows the user to view the
    applied filter, apply a filter for packet capturing, clear the applied filter, and capture a
    specified number of packets.

    Returns:
        None
    """
    while True:
        if INTERFACE == "":
            print("Error: interface not selected.")
            break
        else:
            print("1 - Show the applied filter")
            print("2 - Apply a filter for packet capturing")
            print("3 - Clear the applied filter for packet capturing")
            print("4 - Capture X packets.")
            print("")
            print("5 - Back")

            option=get_and_validate_option(5)

            if option == 1:
                show_filter()
            elif option == 2:
                menu_filters()
            elif option == 3:
                erase_filter()
            elif option == 4:
                capture_traffic()
            elif option == 5:
                break


def print_packet(i, ip_src, ip_dst, protocol):
    """
    This function prints the information of a network packet.

    Args:
        i (int): The index of the packet.
        ip_src (str): The source IP address of the packet.
        ip_dst (str): The destination IP address of the packet.
        protocol (str): The protocol of the packet.

    Returns:
        None
    """
    print(f"Packet {i}:")
    print(f"   Source IP: {ip_src}")
    print(f"   Destination IP: {ip_dst}")
    print(f"   Protocol: {protocol}")
    print('-' * 40)


def analyze_filtered_packet(i, packet, find_ipsrc, 
                            find_ipdst, find_protocol):
    """
    This function analyzes a filtered network packet and prints its information if 
    it matches the filter criteria.

    Args:
        i (int): The index of the packet.
        packet (pyshark.packet.Packet): The network packet to analyze.
        find_ipsrc (str): The source IP address to search for.
        find_ipdst (str): The destination IP address to search for.
        find_protocol (str): The protocol to search for.

    Returns:
        None
    """
    try:
        ip_src = packet.ip.src
    except:
        ip_src = "Unavailable"
    
    try:
        ip_dst = packet.ip.dst
    except:
        ip_dst = "Unavailable"
    
    try:
        layer = packet.layers
        protocol = layer[0].layer_name
    except:
        layer = ""
        protocol = ""
    
    ip_src_str = str(ip_src)
    ip_dst_str = str(ip_dst)
    protocol_str = str(protocol)

    if (ip_src_str == find_ipsrc
        ) and (ip_dst_str == find_ipdst
        ) and (protocol_str == find_protocol):

        print_packet(i, ip_src_str, ip_dst_str, protocol_str)


def analyze_packet(i, packet):
    """
    This function analyzes a network packet and prints its information.

    Args:
        i (int): The index of the packet.
        packet (pyshark.packet.Packet): The network packet to analyze.

    Returns:
        None
    """
    try:
        ip_src = packet.ip.src
    except:
        ip_src = "Unavailable"
    
    try:
        ip_dst = packet.ip.dst
    except:
        ip_dst = "Unavailable"
    
    try:
        layer = packet.layers
        protocol = layer[0].layer_name
    except:
        layer = ""
        protocol = ""
    
    print_packet(i, ip_src, ip_dst, protocol)


def analyze_trace(src_trace, mode):
    """
    This function analyzes a network trace and prints packet information based on the selected mode.

    Args:
        src_trace (str): The source of the trace ('buffer' or 'imported').
        mode (str): The mode of analysis ('find' or 'total').

    Returns:
        None
    """
    global BUFFER_PACKETS
    file_path = "./data/trace.pcap"


    if mode == "find":
        print("Enter source IP:")
        find_ipsrc=get_str()
        print("Enter destination IP:")
        find_ipdst=get_str()
        print("Enter protocol:")
        find_protocol=get_str()

    if BUFFER_PACKETS is None and src_trace == "buffer":
        print("Error: Capture buffer is empty")
        return
    elif src_trace == "buffer":
        traza = BUFFER_PACKETS
        if mode == "total":
            for i, packet in traza.items():
                analyze_packet(i, packet)
        elif mode == "find":
                for i, packet in traza.items():
                    analyze_filtered_packet(i, packet, find_ipsrc, find_ipdst, find_protocol)
            
    elif src_trace == "imported":
        try:
            traza = pyshark.FileCapture(file_path)
            if mode == "total":
                for i, packet in enumerate(traza, start=1):
                    analyze_packet(i, packet)
            elif mode == "find":
                for i, packet in enumerate(traza, start=1):
                    analyze_filtered_packet(i, packet, find_ipsrc, find_ipdst, find_protocol)
        except:
            return print("Error: The trace.pcap file does not exist")
        

def menu_analyze_trace(src_trace):
    """
    This function displays a menu for analyzing a trace of network packets. It allows the user to
    search packets by source IP, destination IP, and protocol, or to show data of all packets.

    Args:
        src_trace (str): Specifies the source of the trace ("buffer" for captured packets or
                         "imported" for a pcap file).

    Returns:
        None
    """
    while True:
        
        print("1 - Search packets by source IP, destination IP, and protocol.")
        print("2 - Show data of all packets.")
        print("")
        print("3 - Back")

        option = get_and_validate_option(3)

        if option == 3:
            return
        elif option == 1:
             analyze_trace(src_trace, "find")
        elif option == 2:
            analyze_trace(src_trace, "total")
    

def menu_analyze():
    """
    This function displays a menu for analyzing network packets. It allows the user to choose
    between analyzing an imported file or a captured trace.

    Returns:
        None
    """
    while True:
        print("")
        print("1 - Analyze the imported file")
        print("2 - Analyze the captured trace")
        print("")
        print("3 - Back")
        print("")

        option=get_and_validate_option(3)

        if option == 3:
            break
        elif option == 1:
            menu_analyze_trace("imported")
        elif option == 2:
            menu_analyze_trace("buffer")


def menu_main():
    """
    This function displays the main menu and allows the user to select different actions.

    Returns:
        None
    """
    while True:
        if INTERFACE != "":
            print("Interface selected: {}".format(INTERFACE))
            print("")
        print("")
        print("1 - Show and select an available network interface")
        print("2 - Import a .pcap file")
        print("3 - Capture and filter packets")
        print("4 - Analyze trace")
        print("")
        print("5 - Exit")
        print("")

        option=get_and_validate_option(5)

        if option == 1:
            get_interfaces()
        elif option == 2:
            import_pcap_file()
        elif option == 3:
            menu_capture_and_filters()
        elif option == 4:
            menu_analyze()
        elif option == 5:
            break


if __name__ == "__main__":
    """
    The main entry point of the program. If it is not a Windows operating system, the program will be aborted.
    """
    os = get_os()
    if os == "Windows":
        print(cover)
        get_interfaces()
        menu_main()
    else:
        print("Please run the program on a Windows operating system.")