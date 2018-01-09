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
using Quobject.EngineIoClientDotNet.Client.Transports; //for WebSocket class
using Quobject.SocketIoClientDotNet.Client;


namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {

            var config = new IO.Options
            {
                Transports = ImmutableList.Create(WebSocket.NAME/*, Polling.NAME*/),
                ForceNew = true,
                AutoConnect = false,
                Timeout = 5000,
                ReconnectionDelay = 5000,
                ReconnectionDelayMax = 5000,
                ReconnectionAttempts = int.MaxValue
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
            socket.Emit("message", () => { }, "test");

            Console.ReadLine();
        }
    }
}
