using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;
using System.IO;
using MultiSCPSLServer;
namespace SCPSLServerHook
{

    public class ServerConfigHooker : IEntryPoint
    {

        ServerHookCallback hookCallback = null;

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr FindFirstFileWDelegate(String fileName, IntPtr lpFindFileData);

        [UnmanagedFunctionPointer(
            CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr CreateFileWDelegate(
            String fileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "FindFirstFileW", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr FindFirstFileW(String fileName, IntPtr lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFileW(
            String fileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile
            );

        static IntPtr FindFirstFileWHook(String fileName, IntPtr lpFindFileData)
        {
            ServerConfigHooker main = (ServerConfigHooker)HookRuntimeInfo.Callback;
            string newFileName = ((ServerHookCallback)main.hookCallback).OnFindFirstFile(fileName);
            return FindFirstFileW(newFileName, lpFindFileData);
        }

        static IntPtr CreateFileWHook(
            String fileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile
            )
        {
            ServerConfigHooker main = (ServerConfigHooker)HookRuntimeInfo.Callback;
            string newFileName = ((ServerHookCallback)main.hookCallback).OnCreateFile(fileName);
            return CreateFileW(
                newFileName,
                dwDesiredAccess,
                dwShareMode, lpSecurityAttributes,
                dwCreationDisposition,
                dwFlagsAndAttributes,
                hTemplateFile
            );
        }

        public ServerConfigHooker(RemoteHooking.IContext context, string channel_name)
        {
            hookCallback = RemoteHooking.IpcConnectClient<ServerHookCallback>(channel_name);
        }

        public void Run(RemoteHooking.IContext context, string channel_name)
        {
            try
            {
                LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"), new CreateFileWDelegate(CreateFileWHook), this).ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "FindFirstFileW"), new FindFirstFileWDelegate(FindFirstFileWHook), this).ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
            catch (Exception)
            {

            }
            //RemoteHooking.WakeUpProcess();
            for (; ; )
            {
                Thread.Sleep(500);
            }
        }
    }
}