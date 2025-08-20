#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>


#define MAX_DEVICES 1337
#define DEV_NAME    16
#define MAX_SLOTS   72

typedef struct device device;

typedef struct device
{
    device* next;
    int uid;
    int count;
    char device_name[DEV_NAME];
    void (*free)(void*);
    int (*check)(char*, unsigned int);
    unsigned int access_count;
    unsigned int used_slots;
    unsigned int free_slots;
    char* data;
} device;

device* _device = NULL;
int dev_count = 0;


void device_get(device* device)
{
    device->access_count++;
}


void device_put(device* device)
{
    device->access_count--;

    if(0 == device->access_count)
    {
        free(device);
    }
}


void append_device(device* new_device)
{
    device* last_device = NULL;

    if(NULL == _device)
    {
        _device = new_device;
    }

    else
    {
        last_device = _device;

        while(NULL != last_device->next)
        {
            last_device = last_device->next;
        }
        
        last_device->next = new_device;
        new_device->next = NULL;
    }

    new_device->count = dev_count;
    dev_count++;
    device_get(new_device);
}


void unlink_device(device* target_device)
{
    device* next_device = _device;

    if(target_device == _device)
    {
        _device = target_device->next;
        next_device = NULL;
    }

    while(NULL != next_device)
    {
        if(target_device == next_device->next)
        {
            next_device->next = target_device->next;
            break;
        }

        next_device = next_device->next;
    }

    dev_count--;
    device_put(target_device);
}


device* retrieve_device(int uid)
{
    device* next_device = _device;
    device* target_device = NULL;

    while(NULL != next_device)
    {
        if(uid == next_device->uid)
        {
            target_device = next_device;
            break;
        }

        next_device = next_device->next;
    }

    if(target_device)
    {
        device_get(target_device);
    }

    return target_device;
}


int dev_chk(char* data, unsigned int size)
{
    int ret = 0;

    if(NULL == data)
    {
        printf("[!] Device has no data registered\n");
        goto done;
    }

    ret = *(int*)data;

    printf("[!] Prepare for data stream:\n");
    fwrite(data, 1, size, stdout);
    printf("\n");

done:
    return ret;
}


device* initialize_device(int uid)
{
    device* new_device = NULL;
    char dummy = 0;

    new_device = malloc(sizeof(device));

    if(NULL == new_device)
    {
        goto done;
    }

    memset(new_device, 0, sizeof(device));

    new_device->uid = uid;
    new_device->check = dev_chk;
    new_device->free = free;
    new_device->free_slots = MAX_SLOTS;
    device_get(new_device);

    if(retrieve_device(uid))
    {
        printf("[-] Device already exists!\n");
        goto done;
    }

    fread(&dummy, 1, 1, stdin);
    printf("[!] Enter device name\n");
    fread(new_device->device_name, 1, DEV_NAME, stdin);

    append_device(new_device);

    printf("[+] Device %d initialized!\n", uid);

done:
    return new_device;
}


device* clone_device(int uid)
{
    device* new_device = NULL;
    device* target_device = NULL;

    new_device = malloc(sizeof(device));

    if(NULL == new_device)
    {
        goto done;
    }

    memset(new_device, 0, sizeof(device));
    device_get(new_device);
    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    memcpy(new_device, target_device, sizeof(device));
    new_device->access_count = 1;
    append_device(new_device);

    printf("[+] Device %d cloned!\n", uid);

done:
    if(target_device)
    {
        device_put(target_device);
    }
    return new_device;
}


device* close_device(int uid)
{
    device* target_device = NULL;

    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    if(target_device->data)
    {
        target_device->free(target_device->data);
        target_device->data = NULL;
    }

    unlink_device(target_device);
    printf("[+] Device %d closed\n", uid);

done:
    return target_device;
}


device* register_device_data(int uid, int req_slots)
{
    device* target_device = NULL;

    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    if(NULL == target_device->data)
    {
        char* data = malloc(MAX_SLOTS);

        if(NULL == data)
        {
            goto done;
        }

        target_device->data = data;
    }

    if(target_device->free_slots - req_slots > 0)
    {
        char dummy = 0;
        char* cursor = target_device->data + target_device->used_slots;
        
        fread(&dummy, 1, 1, stdin);
        printf("[!] Submit the data\n");
        fread(cursor, 1, req_slots, stdin);
        target_device->used_slots += req_slots;
        target_device->free_slots -= req_slots;
        printf("[+] Data for device %d registered!\n", uid);
    }

    else
    {
        printf("[-] Data slots are full!\n");
    }

done:
    return target_device;
}


device* unregister_device_data(int uid)
{
    device* target_device = NULL;

    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    if(target_device->data)
    {
        target_device->free(target_device->data);
        target_device->data = NULL;
        target_device->used_slots = 0;
        target_device->free_slots = MAX_SLOTS;
        printf("[+] Device data %d unregistered\n", uid);
    }

done:
    return target_device;
}


device* check_device(int uid)
{
    int ret = -1;
    device* target_device = NULL;

    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    ret = target_device->check(target_device->data, target_device->used_slots);

    if(0 != ret)
    {
        printf("[-] Device malfunction, error code: %0x\n", ret);
    }

done:
    return target_device;
}


device* display_device_statistics(int uid)
{
    device* target_device = NULL;

    target_device = retrieve_device(uid);

    if(NULL == target_device)
    {
        goto done;
    }

    printf("[+] Device %d statistics:\n", target_device->uid);
    printf("[^] Name: %s\n", target_device->device_name);
    printf("[^] Total data registered: %u \n", target_device->used_slots);
    printf("[^] Free slots: %u \n", target_device->free_slots);
    printf("[^] Access count %u\n", target_device->access_count);
    printf("[^] Total device count: %d\n", dev_count);

done:
    return target_device;
}


void flush_line(int code)
{
    char dummy = 0;
    int ret = 1;

    if(code == EOF)
    {
        printf("[!] No further commands detected...\n");
        printf("[!] Exiting now, goodbye ^.^\n");
        exit(0);
    }

    printf("[-] Invalid format detected!\n");
    printf("[-] Purging line...\n");

    while(ret == 1)
    {
        ret = fread(&dummy, 1, 1, stdin);

        if((dummy == '\n') || (dummy == 0))
        {
            break;
        }
    }
}


int main (int argc, char ** argv)
{

    while(true)
    {
        device* device = NULL;
        int ret = 0;
        int choice = 0;
        int uid = 0;
        int size = 0;

        setvbuf(stdout, NULL, _IONBF, 0);
        
        printf("[!] Make your choice!\n");
        printf("[1] Initialize device\n");
        printf("[2] Clone device\n");
        printf("[3] Register device data\n");
        printf("[4] Check device function\n");
        printf("[5] Unregister device data\n");
        printf("[6] Display device statistics\n");
        printf("[7] Close device\n");

        ret = scanf("%d",&choice);

        if(ret != 1)
        {
            flush_line(ret);
            continue;
        }

        printf("[!] Enter the integer uid for your device\n");
        ret = scanf("%d", &uid);

        if(ret != 1)
        {
            flush_line(ret);
            continue;
        }

        switch(choice)
        {
            case 1:
                if(dev_count == MAX_DEVICES)
                {
                    printf("[-] Maximum number of devices reached!\n");
                    printf("[-] In order to create a new device, close an existing device\n");
                    continue;
                }

                device = initialize_device(uid);
                break;
            case 2:
                device = clone_device(uid);
                break;
            case 3:
                printf("[!] Enter size of device data\n");
                ret = scanf("%d", &size);

                if(ret != 1)
                {
                    flush_line(ret);
                    continue;
                }

                if((size > 0) && (size < MAX_SLOTS))
                {
                    device = register_device_data(uid, size);
                }

                else
                {
                    printf("[-] Data too large\n");
                }
                
                break;
            case 4:
                device = check_device(uid);
                break;
            case 5:
                device = unregister_device_data(uid);
                break;
            case 6:
                device = display_device_statistics(uid);
                break;
            case 7:
                device = close_device(uid);
                break;
            default:
                printf("[-] Invalid option %d\n", choice);
        }

        if(device)
        {
            device_put(device);
        }

        else
        {
            printf("[-] An error occurred\n");
        }
   }

    return 0;
}