import socket

import libnfs


# ==================== FUNCTIONS ==================== #


def nfs_get(nfs_context):
    print_title("NFS GET")
    name = input("file name >> ")
    try:
        print(nfs_context.open(name, mode='r').read())
    except Exception as e:
        print("File not found.")
        print(str(e))
    return


def nfs_find(nfs_context):
    print_title("NFS FIND")
    name = input("file name >> ")
    try:
        file = nfs_context.open(name, mode='r')
        print("File " + name + " found.")
        print(str(file.fstat()))
    except Exception as e:
        print("File not found.")
        print(str(e))
    return


def nfs_list(nfs_context):
    print_title("NFS LIST")
    name = input("directory to list (blank for root directory) >> ")
    if name is None or name is "":
        name = "."
    try:
        print(str(nfs_context.listdir(name)))
    except Exception as e:
        print("Error printing directory.")
        print(str(e))
    return


def nfs_create(nfs_context):
    print_title("NFS CREATE")
    name = input("file name >> ")
    try:
        file = nfs_context.open(name, mode='w+')
        print("File " + name + " successfully created")
    except Exception as e:
        print("Error creating file.")
        print(str(e))
    return


# ==================== MENU ==================== #


def default(nfs_context=None):
    print("Invalid choice, please try again.")
    return


def menu(nfs_context=None):
    print_title("NFS MITM CLIENT COMMANDS")
    print("//")
    print("// G -\tGet")
    print("// F -\tFind")
    print("// L -\tList")
    print("// C -\tCreate (File)")
    print("// D -\tDelete")
    print("//")
    print("// M -\tPrint this menu")
    print_title()
    return


def case_statement(selection):
    tmp = str(selection).lower()[0]
    switcher = {
        'g': nfs_get,
        'f': nfs_find,
        'l': nfs_list,
        'c': nfs_create,
        'm': menu,
    }
    return switcher.get(tmp, default)


def print_title(title=""):
    total = 60
    x = total - len(title)
    print("\n// " + title, end='')
    for i in range(0, x):
        print("=", end='')
    print("")

# ==================== MAIN ==================== #


def get_mount_point_from_api():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 2050))
    data, address = sock.recvfrom(65412)
    sock.close()
    return data.decode('utf-8')


def run(server_ip, mount_point):
    if server_ip == '127.0.0.1' and mount_point == '/mnt/':  # credentials not provided, use api
        print("Getting NFS MOUNT info from API...")
        mount_url = get_mount_point_from_api()
    else:  # credentials provided
        if mount_point[0] != '/':
            mount_point = '/' + mount_point
        mount_url = 'nfs://' + server_ip + mount_point

    print("\t- " + str(mount_url) + "\n")
    nfs = libnfs.NFS(mount_url)
    menu(nfs)

    while True:
        print("===========================\nChoose option")
        choice = input(">> ")
        func = case_statement(choice)
        func(nfs)


if __name__ == "__main__":

    import optparse
    parser = optparse.OptionParser()

    parser.add_option(
        '-s', '--server-ip',
        dest='server_ip', default='127.0.0.1',
        help='NFS server IP address to bind to')
    parser.add_option(
        '-m', '--mount-point',
        dest='mount_point', default='/mnt/',
        help='ABSOLUTE, remote filepath to mount')
    options, args = parser.parse_args()

    run(options.server_ip, options.mount_point)
