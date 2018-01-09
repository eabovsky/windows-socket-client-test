using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Quobject.SocketIoClientDotNet.Client;


namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var socket = IO.Socket("https://socketlab.screenmeet.com");
            socket.On(Socket.EVENT_CONNECT, () =>
            {
                Console.WriteLine("Connected");
            })
            .On(Socket.EVENT_DISCONNECT, () =>
            {
                Console.WriteLine("Disconnected");
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
