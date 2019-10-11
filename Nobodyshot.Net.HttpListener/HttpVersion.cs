#if DNXCORE50
using System;

namespace Nobodyshot.Net
{
    internal class HttpVersion
    {
        public static readonly Version Version10;
        //
        // Summary:
        //     Defines a System.Version instance for HTTP 1.1.
        public static readonly Version Version11;

        static HttpVersion()
        {
            Version10 = new Version(1, 0);
            Version11 = new Version(1, 1);
        }

    }
}

#endif