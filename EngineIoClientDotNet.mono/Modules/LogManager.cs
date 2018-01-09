using System;

namespace Quobject.EngineIoClientDotNet.Modules
{
    public class LogManager
    {
        private const string LogFileName = "SocketTrace.txt";
        private readonly string _logType;
        private static readonly LogManager EmptyLogger = new LogManager(null);

        private static System.IO.StreamWriter _file;

        public static bool Enabled = true;
        public static bool RaiseEvent = false;

        public static event EventHandler<string> LogEvent;

        #region Statics

        public static void SetupLogManager()
        {}

        public static LogManager GetLogger(string type)
        {
            var result = new LogManager(type);
            return result;
        }

        public static LogManager GetLogger(Type type)
        {
            return GetLogger(type.ToString());
        }

        public static LogManager GetLogger(System.Reflection.MethodBase methodBase)
        {
#if DEBUG
            var type = $"{methodBase.DeclaringType?.ToString() ?? string.Empty}#{methodBase.Name}";
            return GetLogger(type);
#else
            return EmptyLogger;
#endif
        }

        #endregion

        public LogManager(string type)
        {
            _logType = type;
        }

        //[Conditional("DEBUG")]
        public void Info(string msg)
        {
            if (!Enabled && !RaiseEvent)
            {
                return;
            }

            msg = Global.StripInvalidUnicodeCharacters(msg);
            var msg1 = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss fff} [{_logType}] - {msg}";
            if (Enabled)
            {
                if (_file == null)
                {
                    var logFile = System.IO.File.Create(LogFileName);
                    _file = new System.IO.StreamWriter(logFile)
                    {
                        AutoFlush = true
                    };
                }
                _file.WriteLine(msg1);
            }

            if (RaiseEvent)
            {
                LogEvent?.Invoke(null, msg1);
            }
        }

        //[Conditional("DEBUG")]
        public void Error(string p, Exception exception)
        {
            Info($"ERROR {p} {exception.Message} {exception.StackTrace}");
            if (exception.InnerException != null)
            {
                Info($"ERROR exception.InnerException {p} {exception.InnerException.Message} {exception.InnerException.StackTrace}");
            }
        }

        //[Conditional("DEBUG")]
        internal void Error(Exception e)
        {
            Error("", e);
        }
    }
}