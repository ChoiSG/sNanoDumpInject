using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace sNanoDumpInject.DInvoke
{
    public static class Generic
    {
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }


        public static object DynamicApiInvoke(string dllName, string functionName, Type functionDelegateType, ref object[] parameters, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var pFunction = GetLibraryAddress(dllName, functionName);
            return DynamicFunctionInvoke(pFunction, functionDelegateType, ref parameters);
        }


        public static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
        {
            var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
            return funcDelegate.DynamicInvoke(parameters);
        }


        public static IntPtr LoadModuleFromDisk(string dllPath)
        {
            var uModuleName = new Data.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, dllPath);

            var hModule = IntPtr.Zero;
            var callResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);

            if (callResult != Data.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
                return IntPtr.Zero;

            return hModule;
        }


        public static IntPtr GetLoadedModuleAddress(string dllName)
        {
            var modules = Process.GetCurrentProcess().Modules;

            foreach (ProcessModule module in modules)
            {
                if (module.FileName.EndsWith(dllName, StringComparison.OrdinalIgnoreCase))
                    return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        public static Data.PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            var peMetaData = new Data.PE.PE_META_DATA();

            try
            {
                var e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + 0x3c));
                peMetaData.Pe = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + e_lfanew));

                if (peMetaData.Pe != 0x4550)
                    throw new InvalidOperationException("Invalid PE signature.");

                peMetaData.ImageFileHeader = (Data.PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((ulong)pModule + e_lfanew + 0x4), typeof(Data.PE.IMAGE_FILE_HEADER));

                var optHeader = (IntPtr)((ulong)pModule + e_lfanew + 0x18);
                var peArch = (ushort)Marshal.ReadInt16(optHeader);

                switch (peArch)
                {
                    case 0x010b:
                        peMetaData.Is32Bit = true;
                        peMetaData.OptHeader32 =
                            (Data.PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(optHeader,
                                typeof(Data.PE.IMAGE_OPTIONAL_HEADER32));
                        break;

                    case 0x020b:
                        peMetaData.Is32Bit = false;
                        peMetaData.OptHeader64 =
                            (Data.PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(optHeader,
                                typeof(Data.PE.IMAGE_OPTIONAL_HEADER64));
                        break;

                    default:
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }

                var sectionArray = new Data.PE.IMAGE_SECTION_HEADER[peMetaData.ImageFileHeader.NumberOfSections];

                for (var i = 0; i < peMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    var sectionPtr = (IntPtr)((ulong)optHeader + peMetaData.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                    sectionArray[i] = (Data.PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(sectionPtr, typeof(Data.PE.IMAGE_SECTION_HEADER));
                }

                peMetaData.Sections = sectionArray;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }

            return peMetaData;
        }
    }

    public static class Native
    {
        public static Data.Native.NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(Delegates.NtCreateThreadEx), ref funcargs);

            // Update the modified variables
            threadHandle = (IntPtr)funcargs[0];

            return retValue;
        }

        public static Data.Native.NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
        {
            object[] funcargs =
            {
                sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtCreateSection", typeof(Delegates.NtCreateSection), ref funcargs);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Unable to create section, " + retValue);

            sectionHandle = (IntPtr)funcargs[0];
            maximumSize = (ulong)funcargs[3];

            return retValue;
        }

        public static Data.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            object[] funcargs =
            {
                hProc, baseAddr
            };

            var result = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtUnmapViewOfSection", typeof(Delegates.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static Data.Native.NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
        {
            object[] funcargs =
            {
                sectionHandle, processHandle, baseAddress, zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType,
                win32Protect
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtMapViewOfSection", typeof(Delegates.NtMapViewOfSection), ref funcargs);

            if (retValue != Data.Native.NTSTATUS.Success && retValue != Data.Native.NTSTATUS.ImageNotAtBase)
                throw new InvalidOperationException("Unable to map view of section, " + retValue);

            baseAddress = (IntPtr)funcargs[2];
            viewSize = (ulong)funcargs[6];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref Data.Native.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] funcargs =
            {
                destinationString, sourceString
            };

            Generic.DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

            destinationString = (Data.Native.UNICODE_STRING)funcargs[0];
        }

        public static Data.Native.NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref Data.Native.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] funcargs =
            {
                pathToFile, dwFlags, moduleFileName, moduleHandle
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(Delegates.LdrLoadDll), ref funcargs);

            moduleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] funcargs =
            {
                destination, length
            };

            Generic.DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref funcargs);
        }

        public static Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;

                case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new Data.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;

                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(Delegates.NtQueryInformationProcess), ref funcargs);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            var retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessWow64Information, out var pProcInfo);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return Marshal.ReadIntPtr(pProcInfo) != IntPtr.Zero;
        }

        public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            var retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Data.Native.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
        {
            object[] funcargs =
            {
                processHandle, baseAddress, zeroBits, regionSize, allocationType, protect
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(Delegates.NtAllocateVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case Data.Native.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case Data.Native.NTSTATUS.AlreadyCommitted:
                    throw new InvalidOperationException("The specified address range is already committed.");
                case Data.Native.NTSTATUS.CommitmentLimit:
                    throw new InvalidOperationException("Your system is low on virtual memory.");
                case Data.Native.NTSTATUS.ConflictingAddresses:
                    throw new InvalidOperationException("The specified address range conflicts with the address space.");
                case Data.Native.NTSTATUS.InsufficientResources:
                    throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
                case Data.Native.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
                case Data.Native.NTSTATUS.InvalidPageProtection:
                    throw new InvalidOperationException("The specified page protection was not valid.");
                case Data.Native.NTSTATUS.NoMemory:
                    throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
                case Data.Native.NTSTATUS.ObjectTypeMismatch:
                    throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");

            baseAddress = (IntPtr)funcargs[1];
            return baseAddress;
        }

        public static void NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            object[] funcargs =
            {
                processHandle, baseAddress, regionSize, freeType
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(Delegates.NtFreeVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case Data.Native.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case Data.Native.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
            }

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }

        public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
        {
            uint oldProtect = 0;
            object[] funcargs =
            {
                processHandle, baseAddress, regionSize, newProtect, oldProtect
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtProtectVirtualMemory", typeof(Delegates.NtProtectVirtualMemory), ref funcargs);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to change memory protection, " + retValue);

            oldProtect = (uint)funcargs[4];
            return oldProtect;
        }

        public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
        {
            uint bytesWritten = 0;
            object[] funcargs =
            {
                processHandle, baseAddress, buffer, bufferLength, bytesWritten
            };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(Delegates.NtWriteVirtualMemory), ref funcargs);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to write memory, " + retValue);

            bytesWritten = (uint)funcargs[4];
            return bytesWritten;
        }


        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// // These delegates may also be used directly.
        ///
        /// // Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //  Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        public struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtCreateThreadEx(
                out IntPtr threadHandle,
                Data.Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtOpenProcess(
               ref IntPtr ProcessHandle,
               uint DesiredAccess,
               ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
               ref Data.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtWaitForSingleObject(
                IntPtr Object,
                bool Alertable,
                IntPtr Timeout
                );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtCreateSection(
                ref IntPtr sectionHandle,
                uint desiredAccess,
                IntPtr objectAttributes,
                ref ulong maximumSize,
                uint sectionPageProtection,
                uint allocationAttributes,
                IntPtr fileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtMapViewOfSection(
                IntPtr sectionHandle,
                IntPtr processHandle,
                out IntPtr baseAddress,
                IntPtr zeroBits,
                IntPtr commitSize,
                IntPtr sectionOffset,
                out ulong viewSize,
                uint inheritDisposition,
                uint allocationType,
                uint win32Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint LdrLoadDll(
                IntPtr pathToFile,
                uint dwFlags,
                ref Data.Native.UNICODE_STRING moduleFileName,
                ref IntPtr moduleHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref Data.Native.UNICODE_STRING destinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string sourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtQueryInformationProcess(
                IntPtr processHandle,
                Data.Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref uint returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtAllocateVirtualMemory(
                IntPtr processHandle,
                ref IntPtr baseAddress,
                IntPtr zeroBits,
                ref IntPtr regionSize,
                uint allocationType,
                uint protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtFreeVirtualMemory(
                IntPtr processHandle,
                ref IntPtr baseAddress,
                ref IntPtr regionSize,
                uint freeType);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtProtectVirtualMemory(
                IntPtr processHandle,
                ref IntPtr baseAddress,
                ref IntPtr regionSize,
                uint newProtect,
                ref uint oldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtWriteVirtualMemory(
                IntPtr processHandle,
                IntPtr baseAddress,
                IntPtr buffer,
                uint bufferLength,
                ref uint bytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint LdrGetProcedureAddress(
                IntPtr hModule,
                IntPtr functionName,
                IntPtr ordinal,
                ref IntPtr functionAddress);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint RtlGetVersion(
                ref Data.Native.OSVERSIONINFOEX versionInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtOpenFile(
                ref IntPtr fileHandle,
                Data.Win32.Kernel32.FileAccessFlags accessFlags,
                ref Data.Native.OBJECT_ATTRIBUTES objectAttributes,
                ref Data.Native.IO_STATUS_BLOCK ioStatusBlock,
                Data.Win32.Kernel32.FileShareFlags shareAccess,
                Data.Win32.Kernel32.FileOpenFlags openOptions);


        }
    }
}

