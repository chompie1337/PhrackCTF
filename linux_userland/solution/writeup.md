
# Writeup very-normal-device

There are a total of 4 *exploitable* vulnerabilities in the service. They are as follows:

- Dangling pointer: The `clone_device` function copies a device from the global `_device` list with a given UID. The function copies everything within the structure via `memcpy`. While `access_count` and `next` pointer are correctly set after the copy, the `data` pointer is left intact in the clone. This creates a possibility for a use after free - if the original device is closed, its data is unregistered and freed.
- Improper null termination: In `initialize_device`, the function `fread` is used to intialize the `device_name` array of a device. This function does not null terminate the buffer. Therefore, it is possible to initialize a device with the maximum length that is not null terminated. The `display_device_statistics` command prints the statistics of the device, which utilizes `printf` with `%s` formatter for `device_name`. If `device_name` is not a null terminated string, `printf` will leak past the bounds of the array and trigger an information disclosure. 
- Heap overflow due to integer promotion: In `register_device_data`, there is a size check on the data to ensure a heap overflow does not occur. However, the check `if(target_device->free_slots - req_slots > 0)` is incorrect. This is because `free_slots` is an unsigned int and `req_slots` is a signed int. Because of this, the comparison becomes unsigned. This allows the check to pass if `req_slots` is larger than the available free space and triggers a heap overflow.
- Reference count leak: In the `initialize_device` function, there is a check to see if a device with the specified UID already exists. It is done via `retrieve_device` which increments the reference count (`access_count`) of the device. If a duplicate entry is found, the reference is never released. This makes it possible to arbitrarily increment the reference count of a given device. If done enough times, an integer overflow can be triggered on `access_count`, wrapping the integer value back to 0. When this happens, the device is freed without being unlinked from the global `_device` list, making a use-after-free possible.


## Possible Solution

The `sol.py` script exploits the service using the first vulnerability listed above. 

It does so with the following steps:

1. First, we initialize a device with uid=1337, and register some data to it. This allocates some memory and stores the pointer in `data`.
2. Clone the uid=1337 device
3.  Unregister data for device uid=1337, which frees the data pointer and overwrites `data = NULL` in the original device. 
4. Initialize a new device uid=333. Because data and devices are the same size, the device buffer will be the same as the `data` that was just freed. Remember, the clone of uid=1337 still has a pointer to it!
5. Register data for device uid=333, the contents of the data will be of our desired shell command. In this case, `cat /flag.txt`. 
6. Close the original device uid=1337. This unlinks and frees the original device uid=1337. Now, when we try to access device uid=1337, we will reach the cloned device, which has the stale `data` pointer. Remember, the stale `data` pointer now points to our new device uid=333. 
7. Now we check device statistics for device uid=1337 with the stale data pointer. This allows us to leak the contents of the entire uid=333 device. With this information, we can break ASLR. Using the address of `free`, we can calculate the address of `system`. We also get the address of `data`, which points to our shell command.
8. We now unregister data for device uid=1337 again. This frees the `data` pointer, which also points to device uid=333.
9. Register data for device uid=1337 again. The allocation for `data` will again be the same pointer to memory we just freed, which is the same as device uid=333. Doing this, we are able to overwrite device uid=333 with whatever data we want. When we register the data, it should correspond to a fake device. We set it up as follows:

```
struct device
{
    device* next = NULL; // NULL so list traversal doesn't break
    int uid = 333;  // Needs to be set properly so we can access the device again
    int count;  // Arbitrary 
    char device_name[DEV_NAME]; // Abitrary 
    void (*free)(void*);  // Arbitrary 
    int (*check)(char*, unsigned int) = system;  // Address of system().
    unsigned int access_count = 1; // Shouldn't matter but set as 1 to keep system sane
    unsigned int used_slots; // Arbitrary
    unsigned int free_slots; // Arbitrary
    char* data = data;   // Same as before - the data for device uid=333 contains the command we want to pass to system. We leaked this in step #7. 
} device;

```

10. Finally, we check device uid=333. Since the device contains all of our controlled data, the check pointer now points to system. In the function `check_device`, system will be called with the `data` parameter, which contains our desired command. 
11. Win :)