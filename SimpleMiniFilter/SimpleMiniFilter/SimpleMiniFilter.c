/*++

Module Name:

    SimpleMiniFilter.c

Abstract:

    This is the main module of the SimpleMiniFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntimage.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
SimpleMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
SimpleMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
SimpleMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
SimpleMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
SimpleMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SimpleMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
SimpleMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
SimpleMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SimpleMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
SimpleMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SimpleMiniFilterUnload)
#pragma alloc_text(PAGE, SimpleMiniFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, SimpleMiniFilterInstanceSetup)
#pragma alloc_text(PAGE, SimpleMiniFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, SimpleMiniFilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
     0,
     SimpleMiniFilterPreOperation,
     SimpleMiniFilterPostOperation },

     { IRP_MJ_CREATE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

#if 0 // TODO - List all of the requests to filter.

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_READ,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      SimpleMiniFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      SimpleMiniFilterPreOperation,
      SimpleMiniFilterPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    SimpleMiniFilterUnload,                           //  MiniFilterUnload

    SimpleMiniFilterInstanceSetup,                    //  InstanceSetup
    SimpleMiniFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    SimpleMiniFilterInstanceTeardownStart,            //  InstanceTeardownStart
    SimpleMiniFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
SimpleMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
SimpleMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
SimpleMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterInstanceTeardownStart: Entered\n") );
}


VOID
SimpleMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
SimpleMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

// 判断是否为DLL文件
BOOLEAN IsValidDll(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject)
{
    ULONG Size = 0;
    PUCHAR Buffer[1024] = { 0 }; // 要用堆空间
    LARGE_INTEGER Offset = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    
    Status = FltReadFile(Instance, FileObject, &Offset, 1024, Buffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &Size, NULL, NULL);

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)Buffer;
    if (IMAGE_NT_SIGNATURE != pNt->Signature) {
        return FALSE;
    }

    BOOLEAN isDll = pNt->OptionalHeader.DllCharacteristics & IMAGE_FILE_DLL;
    if (isDll) return TRUE;
    else return FALSE; 
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
SimpleMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    ULONG     ProcessID = 0;
    PEPROCESS EProcess = NULL;
    NTSTATUS  Status = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    UNICODE_STRING OriName = { 0 };
    PWCHAR NewName = NULL;

    EProcess = FltGetRequestorProcess(Data);
    ProcessID = FltGetRequestorProcessId(Data);

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data || !Data->Iopb || !Data->Iopb->TargetFileObject)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 重定向文件
    RtlInitUnicodeString(&OriName, L"\\System32\\1.txt");
    if (RtlEqualUnicodeString(&Data->Iopb->TargetFileObject->FileName, &OriName, TRUE))
    {
        NewName = (PWCHAR)ExAllocatePool(NonPagedPoolNx, 256);
        if (NewName)
        {
            // 注意新路径需要包含\\Device\\HardDiskVolume3卷信息
            wcscpy(NewName, L"\\SystemRoot\\System32\\2.txt"); // 重定向
            ExFreePool(Data->Iopb->TargetFileObject->FileName.Buffer);
            RtlInitUnicodeString(&Data->Iopb->TargetFileObject->FileName, NewName);
            Data->Iopb->TargetFileObject->RelatedFileObject = NULL;
            Data->IoStatus.Status = STATUS_REPARSE;
            Data->IoStatus.Information = IO_REPARSE;
            FltSetCallbackDataDirty(Data); // simrep中没有这行
            return FLT_PREOP_COMPLETE;
        }
    }

    //// DLL注入拦截
    //// 检查是不是映射文件操作
    //if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
    //{
    //    // 获取文件名信息
    //    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);
    //    if (NT_SUCCESS(Status))
    //    {
    //        // 转换文件名信息
    //        Status = FltParseFileNameInformation(NameInfo);
    //        if (NT_SUCCESS(Status))
    //        {
    //            // 本次操作的文件对象
    //            Data->Iopb->TargetFileObject;
    //            // 过滤到的文件不止DLL文件,可以做个检测
    //            if (IsValidDll(FltObjects->Instance, FltObjects->FileObject))
    //            {
    //                // 根据已获得的PID,NameInfo,FileObject决定动作
    //                // ......
    //                FltReleaseFileNameInformation(NameInfo);
    //                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    //                return FLT_PREOP_COMPLETE;
    //                // 注意拦截后会弹出权限不足的窗口
                    // 使用STATUS_INSUFFICIENT_RESOURCES就不会弹窗
    //            }
    //        }
    //        // 释放文件名内存空间
    //        FltReleaseFileNameInformation(NameInfo);
    //    }
    //}

    if (SimpleMiniFilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    SimpleMiniFilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("SimpleMiniFilter!SimpleMiniFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID
SimpleMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("SimpleMiniFilter!SimpleMiniFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
SimpleMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
SimpleMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("SimpleMiniFilter!SimpleMiniFilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
SimpleMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
