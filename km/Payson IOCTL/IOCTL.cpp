#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

UNICODE_STRING DriverName, SymbolicLinkName;

typedef struct _SystemBigpoolEntry {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SystemBigpoolEntry, * PSystemBigpoolEntry;

typedef struct _SystemBigpoolInformation {
    ULONG Count;
    SystemBigpoolEntry AllocatedInfo[1];
} SystemBigpoolInformation, * PSystemBigpoolInformation;

typedef enum _SystemInformationClass {
    SystemBigpoolInformationClass = 0x42,
} SystemInformationClass;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SystemInformationClass systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

#define PaysonRead CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1363, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define PaysonBase CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1369, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define PaysonSecurity 0x85F8AC8

#define Win1803 17134
#define Win1809 17763
#define Win1903 18362
#define Win1909 18363
#define Win2004 19041
#define Win20H2 19569
#define Win21H1 20180

#define PageOffsetSize 12
static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;

typedef struct _ReadWriteRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
    BOOLEAN Write;
} ReadWriteRequest, * PReadWriteRequest;

typedef struct _BaseAddressRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG* Address;
} BaseAddressRequest, * PBaseAddressRequest;

NTSTATUS ReadPhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
    MM_COPY_ADDRESS CopyAddress = { 0 };
    CopyAddress.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

INT32 GetWindowsVersion() {
    RTL_OSVERSIONINFOW VersionInfo = { 0 };
    RtlGetVersion(&VersionInfo);
    switch (VersionInfo.dwBuildNumber) {
    case Win1803:
        return 0x0278;
        break;
    case Win1809:
        return 0x0278;
        break;
    case Win1903:
        return 0x0280;
        break;
    case Win1909:
        return 0x0280;
        break;
    case Win2004:
        return 0x0388;
        break;
    case Win20H2:
        return 0x0388;
        break;
    case Win21H1:
        return 0x0388;
        break;
    default:
        return 0x0388;
    }
}

UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;
    uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)Process + 0x28);
    if (process_dirbase == 0)
    {
        ULONG user_diroffset = GetWindowsVersion();
        process_dirbase = *(uintptr_t*)((UINT8*)Process + user_diroffset);
    }
    if ((process_dirbase >> 0x38) == 0x40)
    {
        uintptr_t SavedDirBase = 0;
        bool Attached = false;
        if (!Attached)
        {
            KAPC_STATE apc_state{};
            KeStackAttachProcess(Process, &apc_state);
            SavedDirBase = __readcr3();
            KeUnstackDetachProcess(&apc_state);
            Attached = true;
        }
        if (SavedDirBase) return SavedDirBase;
        
    }
    return process_dirbase;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
    DirectoryTableBase &= ~0xf;

    UINT64 PageOffset = VirtualAddress & ~(~0ul << PageOffsetSize);
    UINT64 PteIndex = ((VirtualAddress >> 12) & (0x1ffll));
    UINT64 PtIndex = ((VirtualAddress >> 21) & (0x1ffll));
    UINT64 PdIndex = ((VirtualAddress >> 30) & (0x1ffll));
    UINT64 PdpIndex = ((VirtualAddress >> 39) & (0x1ffll));

    SIZE_T ReadSize = 0;
    UINT64 PdpEntry = 0;
    ReadPhysicalMemory(PVOID(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize);
    if (~PdpEntry & 1)
        return 0;

    UINT64 PdEntry = 0;
    ReadPhysicalMemory(PVOID((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize);
    if (~PdEntry & 1)
        return 0;

    if (PdEntry & 0x80)
        return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

    UINT64 PtEntry = 0;
    ReadPhysicalMemory(PVOID((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize);
    if (~PtEntry & 1)
        return 0;

    if (PtEntry & 0x80)
        return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));

    VirtualAddress = 0;
    ReadPhysicalMemory(PVOID((PtEntry & PageMask) + 8 * PteIndex), &VirtualAddress, sizeof(VirtualAddress), &ReadSize);
    VirtualAddress &= PageMask;

    if (!VirtualAddress)
        return 0;

    return VirtualAddress + PageOffset;
}

ULONG64 FindMin(INT32 A, SIZE_T B) {
    INT32 BInt = (INT32)B;
    return (((A) < (BInt)) ? (A) : (BInt));
}

NTSTATUS HandleReadRequest(PReadWriteRequest Request) {
    if (Request->Security != PaysonSecurity)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ProcessBase = GetProcessCr3(Process);
    ObDereferenceObject(Process);

    SIZE_T Offset = NULL;
    SIZE_T TotalSize = Request->Size;

    INT64 PhysicalAddress = TranslateLinearAddress(ProcessBase, (ULONG64)Request->Address + Offset);
    if (!PhysicalAddress)
        return STATUS_UNSUCCESSFUL;

    ULONG64 FinalSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), TotalSize);
    SIZE_T BytesRead = NULL;

    ReadPhysicalMemory(PVOID(PhysicalAddress), (PVOID)((ULONG64)Request->Buffer + Offset), FinalSize, &BytesRead);

    return STATUS_SUCCESS;
}

NTSTATUS HandleBaseAddressRequest(PBaseAddressRequest Request) {
    if (Request->Security != PaysonSecurity)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
    if (!ImageBase)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(Request->Address, &ImageBase, sizeof(ImageBase));
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}

NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = {};
    ULONG BytesReturned = {};
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (IoControlCode == PaysonRead) {
        if (InputBufferLength == sizeof(ReadWriteRequest)) {
            PReadWriteRequest Request = (PReadWriteRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleReadRequest(Request);
            BytesReturned = sizeof(ReadWriteRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }
    else if (IoControlCode == PaysonBase) {
        if (InputBufferLength == sizeof(BaseAddressRequest)) {
            PBaseAddressRequest Request = (PBaseAddressRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleBaseAddressRequest(Request);
            BytesReturned = sizeof(BaseAddressRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    NTSTATUS Status = {};

    Status = IoDeleteSymbolicLink(&SymbolicLinkName);

    if (!NT_SUCCESS(Status))
        return;

    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Device\\{sdfjkn4e78hhsjk-sdfjnas78adasd}");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\{sdfjkn4e78hhsjk-sdfjnas78adasd}");

    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = &UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler;
    DriverObject->DriverUnload = &UnloadDriver;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("\nDbgLog: RegistryPath found.");
    DbgPrint("\nMade by guns.lol/Payson1337");

    return IoCreateDriver(NULL, &InitializeDriver);
}