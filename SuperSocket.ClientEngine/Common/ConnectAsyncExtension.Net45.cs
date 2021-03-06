﻿using System;
using System.Net;
using System.Net.Sockets;

namespace SuperSocket.ClientEngine
{
    public static partial class ConnectAsyncExtension
    {
        internal static bool PreferIPv4Stack()
        {
            return Environment.GetEnvironmentVariable("PREFER_IPv4_STACK") != null;
        }

        public static void ConnectAsync(this EndPoint remoteEndPoint, EndPoint localEndPoint, ConnectedCallback callback, object state)
        {
            var e = CreateSocketAsyncEventArgs(remoteEndPoint, callback, state);

            var preferIp4 = PreferIPv4Stack();
            var socket = PreferIPv4Stack()
                ? new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) 
                : new Socket(SocketType.Stream, ProtocolType.Tcp);
            
            if (localEndPoint != null)
            {
                try
                {
                    socket.ExclusiveAddressUse = false;
                    socket.Bind(localEndPoint);
                }
                catch (Exception exc)
                {
                    callback(null, state, null, exc);
                    return;
                }
            }
                
            socket.ConnectAsync(e);
        }
    }
}
