import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor #para gestionar y limitar los hilos, evitando así errores comunes como el exceso de conexiones máximas.
#from termcolor import colored #pip3 install termcolor

open_sockets = []

def def_handler(sig, frame):
    print(f"\n Saliendo del programa...")

    for socket in open_sockets:
        socket.close()
        sys.exit(1)
    
signal.signal(signal.SIGINT, def_handler) #Ctrl+C

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Victim target to scan")
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range to scan")
    options = parser.parse_args()

    return options.target, options.port

def create_socket():
    s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
    s.timeout(1)

    open_sockets.append(s)
    return s

def port_scanner(port, host):

    s = create_socket()

    try:
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = s.recv(1024).decode(errors='ignore').split("\n")

        if response:
            print(f"El puerto {port} está abierto\n")

            for line in response:
               print(f"{line}") 
        else:  
            print(f"El puerto {port} está abierto")

    except(socket.timeout, ConnectionRefusedError):
        pass

    finally:
        s.close()

def scan_ports(ports, target):

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(port, target), ports)

#    threads = []
#    for port in ports:
#        thread = threading.Thread(target=port_scanner, args=(port, target))
#        threads.append(thread)
#        thread.start()
#     for thread in threads:
#        thread.join()

def parse_ports(ports_str):

    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end+1)
    
    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    
    else:
        return (int(ports_str),)
         
def main():

    target, ports_str = get_arguments()
    ports = parse_ports(ports_str)
    scan_ports(ports,target)   

if __name__ == '__main__':
    main()