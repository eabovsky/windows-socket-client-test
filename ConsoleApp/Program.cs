using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NSspi;
using NSspi.Contexts;
using NSspi.Credentials;
using Quobject.EngineIoClientDotNet.Client.Transports; //for WebSocket class
using Quobject.SocketIoClientDotNet.Client;


namespace ConsoleApp
{
    class Program
    {

        static void testnsspi()
        {
            var packageName = "NTLM";
            ClientCurrentCredential clientCred = new ClientCurrentCredential(packageName);
            //ServerCurrentCredential serverCred = new ServerCurrentCredential(packageName);

            Console.WriteLine("NSSPI Client Auth Principle: " + clientCred.PrincipleName);
            //Console.WriteLine("NSSPI Server Auth Principle: " + serverCred.PrincipleName);

            byte[] NTLMClientToken1 = null;
            byte[] serverToken = null;
            SecurityStatus clientStatus;

            ClientContext client = new ClientContext(
                    clientCred,
                    clientCred.PrincipleName,
                    ContextAttrib.MutualAuth |
                    ContextAttrib.InitIdentify |
                    ContextAttrib.Confidentiality |
                    ContextAttrib.ReplayDetect |
                    ContextAttrib.SequenceDetect |
                    ContextAttrib.Connection |
                    ContextAttrib.Delegate
                );

            clientStatus = client.Init(serverToken, out NTLMClientToken1);

            Console.WriteLine("NSSPI ClientStatus NTLM1: " + clientStatus.ToString());
            Console.WriteLine("NTLMToken1: " + Convert.ToBase64String(NTLMClientToken1));

        }

        static void Main(string[] args)
        {

            //testnsspi();
            
            var config = new IO.Options
            {
                Transports = ImmutableList.Create(WebSocket.NAME/*, Polling.NAME*/),
                ForceNew = true,
                AutoConnect = false,
                Timeout = 60000,
                ReconnectionDelay = 5000,
                ReconnectionDelayMax = 5000,
                ReconnectionAttempts = 0
            };

            var url = new Uri("https://socketlab.screenmeet.com");

            var manager = new Manager(url, config);
            var socket = manager.Socket(url.LocalPath);
            
            socket.On(Socket.EVENT_CONNECT, () =>
            {
                Console.WriteLine("Connected");
            })
            .On(Socket.EVENT_DISCONNECT, () =>
            {
                Console.WriteLine("Disconnected");
            })            
            .On(Socket.EVENT_CONNECT_ERROR, data =>
            {
                Console.WriteLine($"Connect Error: {data}");
            })
            .On(Socket.EVENT_ERROR, data =>
            {
                Console.WriteLine($"Error: {data}");
            })
            .On("message", data =>
            {
                Console.WriteLine(data);
            });

            socket.Connect();
            socket.Emit("message", () => { }, "test 12345");

            Console.ReadLine();
        }
    }
}
