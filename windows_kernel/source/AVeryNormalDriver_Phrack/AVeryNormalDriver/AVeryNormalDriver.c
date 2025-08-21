#include <ntifs.h>
#include "AVNDInternal.h"


KSPIN_LOCK gSpinLock = { 0 };
PVOID gpGlobalPage = NULL;



PVND_PROCESS GetVndProcess(PDEVICE_OBJECT pDeviceObject, HANDLE pid)
{
	PVND_PROCESS pVndProcess = NULL;
	PVND_DEVICE_EXTENSION pDeviceExtension = NULL;

	pDeviceExtension = pDeviceObject->DeviceExtension;

	for (PLIST_ENTRY entry = pDeviceExtension->ProcessMetaDataListHead.Flink; entry && (entry != &pDeviceExtension->ProcessMetaDataListHead); entry = entry->Flink)
	{
		PVND_PROCESS pCurrentEntry = CONTAINING_RECORD(entry, VND_PROCESS, ListEntry);

		if (pCurrentEntry->Pid == pid)
		{
			pVndProcess = pCurrentEntry;
			break;
		}
	}

	return pVndProcess;
}


PVND_PROCESS GetRegisteredVndProcess(PDEVICE_OBJECT pDeviceObject)
{
	PVND_PROCESS pVndProcess = NULL;
	HANDLE pid = PsGetCurrentProcessId();

	pVndProcess = GetVndProcess(pDeviceObject, pid);

	if (NULL == pVndProcess)
	{
		goto done;
	}

	if (!pVndProcess->bRegistered)
	{
		pVndProcess = NULL;
	}

done:
	return pVndProcess;
}


VOID VndDriverUnload(PDRIVER_OBJECT pDriverObject)
{
	KIRQL oldIrql = { 0 };
	UNICODE_STRING symLinkName = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);

	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VeryNormalDriver");
	IoDeleteSymbolicLink(&symLinkName);

	ExFreePool(gpGlobalPage);
	gpGlobalPage = NULL;
	IoDeleteDevice(pDriverObject->DeviceObject);

	KeReleaseSpinLock(&gSpinLock, oldIrql);
}


NTSTATUS VndDispatchCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

BOOLEAN IsPhrackCoded(PVND_PROCESS pVndProcess)
{
	BOOLEAN bIsPhrack = FALSE;

	if (pVndProcess->ulMetadataSize == 0)
	{
		goto done;
	}

	if (!(pVndProcess->Metadata[0] == 'p'))
	{
		goto done;
	}

	bIsPhrack = TRUE;

done:
	return bIsPhrack;
}


NTSTATUS VndRegisterProcess(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulDataSize = 0;
	PIO_STACK_LOCATION pIrpSp = NULL;
	PVND_DEVICE_EXTENSION pDeviceExtension = NULL;
	PVND_USER_PROCESS pVndUserProcess = NULL;
	PVND_PROCESS pVndProcess = NULL;
	PVND_PROCESS pCurrentEntry = NULL;
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);
	pDeviceExtension = pDeviceObject->DeviceExtension;

	if (NULL == pIrp->AssociatedIrp.SystemBuffer)
	{
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
	ulDataSize = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ulDataSize < sizeof(VND_USER_PROCESS))
	{
		status = STATUS_BUFFER_TOO_SMALL;
		goto done;
	}

	ulDataSize -= sizeof(VND_USER_PROCESS);
	pVndUserProcess = pIrp->AssociatedIrp.SystemBuffer;

	if (pVndUserProcess->ulMetadataSize > ulDataSize)
	{
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	ulDataSize = pVndUserProcess->ulMetadataSize;

	if (ulDataSize + (ULONG)sizeof(VND_PROCESS) < ulDataSize)
	{
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	pVndProcess = ExAllocatePool2(POOL_FLAG_NON_PAGED, ulDataSize + sizeof(VND_PROCESS), VND_POOL_TAG);

	if (NULL == pVndProcess)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	pVndProcess->Pid = PsGetCurrentProcessId();
	pVndProcess->ulMetadataSize = ulDataSize;
	RtlCopyMemory(pVndProcess->Metadata, pVndUserProcess->Metadata, ulDataSize);

	pCurrentEntry = GetRegisteredVndProcess(pDeviceObject);

	if (NULL != pCurrentEntry)
	{
		if (ulDataSize > pCurrentEntry->ulMetadataSize)
		{
			ulDataSize = pCurrentEntry->ulMetadataSize;
		}

		RtlCopyMemory(pCurrentEntry->Metadata, pVndProcess->Metadata, ulDataSize);
		ExFreePool(pVndProcess);
		pVndProcess = NULL;
	}

	if (NULL != pVndProcess)
	{
		pVndProcess->bRegistered = TRUE;
		InsertTailList(&pDeviceExtension->ProcessMetaDataListHead, &pVndProcess->ListEntry);
	}

	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&gSpinLock, oldIrql);
	return status;
}


NTSTATUS VndUnregisterProcess(PDEVICE_OBJECT pDeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVND_PROCESS pVndProcess = NULL;
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);

	pVndProcess = GetRegisteredVndProcess(pDeviceObject);

	if (NULL == pVndProcess)
	{
		goto done;
	}

	if (NULL != pVndProcess->pSharedMapMdl)
	{
		MmUnlockPages(pVndProcess->pSharedMapMdl);
		IoFreeMdl(pVndProcess->pSharedMapMdl);
	}

	pVndProcess->bRegistered = FALSE;
	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&gSpinLock, oldIrql);
	return status;
}


NTSTATUS VndCreateUserMapping(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVND_PROCESS pVndProcess = NULL;
	PIO_STACK_LOCATION pIrpSp = NULL;
	ULONG ulSize = 0;
	PVND_USER_PROCESS pVndUserProcess = NULL;
	PMDL pMdl = NULL;
	PVOID pSharedMapData = NULL;
	PVOID pKernelMap = NULL;
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);

	if (NULL == pIrp->AssociatedIrp.SystemBuffer)
	{
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	pVndProcess = GetRegisteredVndProcess(pDeviceObject);

	if (NULL == pVndProcess)
	{
		status = STATUS_NO_MATCH;
		goto done;
	}

	pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
	ulSize = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ulSize < sizeof(VND_USER_PROCESS))
	{
		status = STATUS_BUFFER_TOO_SMALL;
		goto done;
	}

	pVndUserProcess = pIrp->AssociatedIrp.SystemBuffer;
	pSharedMapData = pVndUserProcess->pSharedMapData;

	pMdl = IoAllocateMdl(pSharedMapData, PAGE_SIZE, FALSE, FALSE, NULL);

	if (NULL == pMdl)
	{
		status = STATUS_CANNOT_MAKE;
		goto done;
	}

	if (NULL != pVndProcess->pSharedMapMdl)
	{
		MmUnlockPages(pVndProcess->pSharedMapMdl);
		IoFreeMdl(pVndProcess->pSharedMapMdl);
	}

	__try
	{
		MmProbeAndLockPages(pMdl, UserMode, IoModifyAccess);
		pVndProcess->pSharedMapMdl = pMdl;
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		IoFreeMdl(pVndProcess->pSharedMapMdl);
		pVndProcess->pSharedMapMdl = NULL;
		pVndProcess->pSharedMap = NULL;
		goto done;
	}

	pKernelMap = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	pVndProcess->pSharedMap = pKernelMap;

	if (NULL == pKernelMap)
	{
		goto done;
	}

	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&gSpinLock, oldIrql);
	return status;
}

NTSTATUS VndGetFlag(PDEVICE_OBJECT pDeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVND_PROCESS pVndProcess = NULL;
	KIRQL oldIrql = { 0 };
	UNICODE_STRING uniPath;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	CHAR flag_buff[FLAG_LEN + 1] = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);
	pVndProcess = GetRegisteredVndProcess(pDeviceObject);
	KeReleaseSpinLock(&gSpinLock, oldIrql);

	if (NULL == pVndProcess)
	{
		status = STATUS_NO_MATCH;
		goto done;
	}

	if (!pVndProcess->bIsLeet)
	{
		status = STATUS_ACCESS_DENIED;
		goto done;
	}

	RtlInitUnicodeString(&uniPath, L"\\??\\C:\\Secrets\\flag.txt");
	InitializeObjectAttributes(&objAttr, &uniPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&hFile, GENERIC_READ, &objAttr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		goto done;
	}

	status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, flag_buff, FLAG_LEN, NULL,NULL);

	if (!NT_SUCCESS(status))
	{
		goto done;
	}

	if (iosb.Information != FLAG_LEN)
	{
		status = STATUS_UNEXPECTED_IO_ERROR;
		goto done;
	}

	memcpy(gpGlobalPage, flag_buff, FLAG_LEN + 1);
	status = STATUS_SUCCESS;

done:

	if (hFile)
	{
		ZwClose(hFile);
	}

	return status;
}


NTSTATUS VndUpdateProcessMap(PDEVICE_OBJECT pDeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVND_PROCESS pVndProcess = NULL;
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);
	pVndProcess = GetRegisteredVndProcess(pDeviceObject);

	if (NULL == pVndProcess)
	{
		status = STATUS_NO_MATCH;
		goto done;
	}

	if (NULL == pVndProcess->pSharedMap)
	{
		status = STATUS_INVALID_DEVICE_STATE;
		goto done;
	}

	RtlCopyMemory(pVndProcess->pSharedMap, gpGlobalPage, PAGE_SIZE);
	status = STATUS_SUCCESS;
done:
	KeReleaseSpinLock(&gSpinLock, oldIrql);
	return status;
}


NTSTATUS VndUpdateGlobalMap(PDEVICE_OBJECT pDeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVND_PROCESS pVndProcess = NULL;
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);

	pVndProcess = GetRegisteredVndProcess(pDeviceObject);

	if (NULL == pVndProcess)
	{
		status = STATUS_NO_MATCH;
		goto done;
	}

	if (NULL == pVndProcess->pSharedMap)
	{
		status = STATUS_INVALID_DEVICE_STATE;
		goto done;
	}

	RtlCopyMemory(gpGlobalPage, pVndProcess->pSharedMap, PAGE_SIZE);
	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&gSpinLock, oldIrql);
	return status;
}


NTSTATUS VndDispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG controlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (controlCode)
	{
	case IOCTL_VND_REGISTER_PROCESS:
		status = VndRegisterProcess(pDeviceObject, pIrp);
		break;
	case IOCTL_VND_UNREGISTER_PROCESS:
		status = VndUnregisterProcess(pDeviceObject);
		break;
	case IOCTL_VND_CREATE_MAPPING:
		status = VndCreateUserMapping(pDeviceObject, pIrp);
		break;
	case IOCTL_VND_UPDATE_GLOBAL_MAP:
		status = VndUpdateGlobalMap(pDeviceObject);
		break;
	case IOCTL_VND_UPDATE_PROCESS_MAP:
		status = VndUpdateProcessMap(pDeviceObject);
		break;
	case IOCTL_VND_GET_FLAG:
		status = VndGetFlag(pDeviceObject);
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
	}

	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS VndDispatchCleanup(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVND_PROCESS pVndProcess = NULL;
	HANDLE pid = PsGetCurrentProcessId();
	KIRQL oldIrql = { 0 };

	KeAcquireSpinLock(&gSpinLock, &oldIrql);

	pVndProcess = GetVndProcess(pDeviceObject, pid);

	if (NULL == pVndProcess)
	{
		goto done;
	}

	if (pVndProcess->bRegistered)
	{
		if (NULL != pVndProcess->pSharedMapMdl)
		{
			MmUnlockPages(pVndProcess->pSharedMapMdl);
			IoFreeMdl(pVndProcess->pSharedMapMdl);
		}

		if (IsPhrackCoded(pVndProcess))
		{
			goto done;
		}
	}

	RemoveEntryList(&pVndProcess->ListEntry);

done:

	if (NULL != pVndProcess)
	{
		ExFreePool(pVndProcess);
	}

	KeReleaseSpinLock(&gSpinLock, oldIrql);

	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DeviceName = { 0 };
	UNICODE_STRING SymLinkName = { 0 };
	PDEVICE_OBJECT pDeviceObject = NULL;
	PVND_DEVICE_EXTENSION pDeviceExtension = NULL;

	KeInitializeSpinLock(&gSpinLock);

	pDriverObject->DriverUnload = VndDriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = VndDispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = VndDispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VndDispatchIoControl;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = VndDispatchCleanup;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\VeryNormalDriver");

	status = IoCreateDevice(pDriverObject, sizeof(VND_DEVICE_EXTENSION), &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject);

	if (!NT_SUCCESS(status))
	{
		goto done;
	}

	RtlInitUnicodeString(&SymLinkName, L"\\DosDevices\\VeryNormalDriver");
	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		goto done;
	}

	gpGlobalPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, VND_POOL_TAG);

	if (NULL == gpGlobalPage)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	pDeviceExtension = pDeviceObject->DeviceExtension;
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	InitializeListHead(&pDeviceExtension->ProcessMetaDataListHead);

done:
	return status;
}