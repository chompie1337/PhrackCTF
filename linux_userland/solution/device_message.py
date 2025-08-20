import socket
import time

HOST = "127.0.0.1"  # Replace with service IP
PORT = 41414        # Port service is listening on

DEV_NAME = 16

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
        else:
            serialized_data = b''

        return serialized_data

def bytes_to_hex(byte_data):
    """Convert bytes to a hexadecimal string for debugging."""
    return " ".join(f"{b:02x}" for b in byte_data)

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


def main():
    
    init_device  = DeviceMessage(choice=1, uid=1337, name="ExampleDevice")
    buffer = init_device.to_bytes() 
    
    try:
        # Create a socket to connect to the service
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Connect to the service
            client_socket.connect((HOST, PORT))
            print(f"Connected to service on {HOST}:{PORT}")

            client_socket.sendall(buffer)

            while True:
                print_response(client_socket)



    except ConnectionRefusedError:
        print(f"Could not connect to the service on {HOST}:{PORT}. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()