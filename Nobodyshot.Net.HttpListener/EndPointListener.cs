//
// System.Net.EndPointListener
//
// Author:
//	Gonzalo Paniagua Javier (gonzalo.mono@gmail.com)
//
// Copyright (c) 2005 Novell, Inc. (http://www.novell.com)
// Copyright (c) 2012 Xamarin, Inc. (http://xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#if SECURITY_DEP

#if !DNXCORE50 && !DNX45 && !NET45
extern alias MonoSecurity;
#endif

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using NetUV.Core.Handles;
using NetUV.Core.Buffers;
using System.Threading.Tasks;
using NetUV.Core.Channels;
using System.Text;
using Nobodyshot.Net;

#if !DNXCORE50 && !DNX45 && !NET45
using MonoSecurity::Mono.Security.Authenticode;
#endif


namespace Nobodyshot.Net {
    sealed class EndPointListener
    {
        IPEndPoint endpoint;
        Socket sock;
        Hashtable prefixes;  // Dictionary <ListenerPrefix, HttpListener>
        ArrayList unhandled; // List<ListenerPrefix> unhandled; host = '*'
        ArrayList all;       // List<ListenerPrefix> all;  host = '+'
        X509Certificate2 cert;
        AsymmetricAlgorithm key;
        bool secure;
        Dictionary<HttpConnection, HttpConnection> unregistered;

        System.Threading.Timer timer;



        //========================================== LIBUV

        readonly EventLoop loop;
        public Tcp sockuv;

        //END ============================================


        public static ThreadLibuv thread;


        public EndPointListener(IPAddress addr, int port, bool secure)
        {
            if (secure) {
                this.secure = secure;
                LoadCertificateAndKey(addr, port);
            }

            endpoint = new IPEndPoint(addr, port);
            loop = new EventLoop();

            thread = new ThreadLibuv(16, OnConnection, endpoint);

            thread.StartAsync();
            

            timer = new System.Threading.Timer(OnTimeout, null, 1, Timeout.Infinite);

            prefixes = new Hashtable();
            unregistered = new Dictionary<HttpConnection, HttpConnection>();
                        

           
        }

        public IPEndPoint LocalEndPoint
        {
            get { return endpoint; }
        }



        void LoadCertificateAndKey(IPAddress addr, int port)
        {
#if !DNXCORE50 && !DNX45 && !NET45
            // Actually load the certificate
            try {
				string dirname = Environment.GetFolderPath (Environment.SpecialFolder.ApplicationData);
				string path = Path.Combine (dirname, ".mono");
				path = Path.Combine (path, "httplistener");
				string cert_file = Path.Combine (path, String.Format ("{0}.cer", port));
				if (!File.Exists (cert_file))
					return;
				string pvk_file = Path.Combine (path, String.Format ("{0}.pvk", port));
				if (!File.Exists (pvk_file))
					return;
				cert = new X509Certificate2 (cert_file);
				key = PrivateKey.CreateFromFile (pvk_file).RSA;
			} catch {
				// ignore errors
			}
#else
            throw new NotSupportedException();
#endif

        }

        void OnConnection(Tcp client, Exception error)
        {
            client.UserToken = this;

            EndPointListener epl = this;

            epl.timer.Change(1, Timeout.Infinite);

            ProcessAccept(client);
        }


        void OnTimeout(object unused)
        {
            SocketAsyncEventArgs args = new SocketAsyncEventArgs();
            args.UserToken = this;
            //args.Completed += OnAccept;

            //while (true)
            //{
            //    if (AcceptAsyncOrProcessSync(args))
            //        break;

            //}
        }

        //private bool AcceptAsyncOrProcessSync(SocketAsyncEventArgs e)
        //{
        //    e.AcceptSocket = null;
        //    bool asyn = false;
        //    try
        //    {
        //        asyn = sock.AcceptAsync(e);
        //    }
        //    catch (Exception ex)
        //    {
        //        // Once the listener starts running, it kicks off an async accept,
        //        // and each subsequent accept initiates the next async accept.  At
        //        // point if the listener is torn down, the socket will be disposed
        //        // and the AcceptAsync on the socket can fail with an ODE.  Far from
        //        // ideal, but for now just eat such exceptions.
        //        if( ex is ObjectDisposedException)
        //            return true;
        //    }
        //    if (!asyn)
        //    {
        //        ProcessAccept(e);


        //    }

        //    return asyn;
        //}


        static MemoryStream SoketStream = new MemoryStream();

        private static void ProcessAccept(Tcp accepted)
        {
            EndPointListener epl = (EndPointListener)accepted.UserToken;

            if (accepted == null)
                return;
            if (epl.secure && epl.cert == null)
            {
                accepted.Dispose();
                return;
            }
            HttpConnection conn;
            try
            {
                conn = new HttpConnection(accepted, thread, epl, epl.secure, epl.cert, epl.key);

            }
            catch( Exception ex)
            {
                accepted.Dispose();
                Console.WriteLine(ex.Message);
                return;
            }
			lock (epl.unregistered)
            {
               epl.unregistered[conn] = conn;
            }
            

            conn.ReadLibuv();


        }

        internal void RemoveConnection (HttpConnection conn)
		{
			lock (unregistered) {
				unregistered.Remove (conn);
			}
		}

		public bool BindContext (HttpListenerContext context)
		{
			HttpListenerRequest req = context.Request;
			ListenerPrefix prefix;
			HttpListener listener = SearchListener (req.Url, out prefix);
			if (listener == null)
				return false;

			context.Listener = listener;
			context.Connection.Prefix = prefix;
			return true;
		}

		public void UnbindContext (HttpListenerContext context)
		{
			if (context == null || context.Request == null)
				return;

			context.Listener.UnregisterContext (context);
		}

		HttpListener SearchListener (Uri uri, out ListenerPrefix prefix)
		{
			prefix = null;
			if (uri == null)
				return null;

			string host = uri.Host;
			int port = uri.Port;
			string path = HttpUtility.UrlDecode (uri.AbsolutePath);
			string path_slash = path [path.Length - 1] == '/' ? path : path + "/";
			
			HttpListener best_match = null;
			int best_length = -1;

			if (host != null && host != "") {
				Hashtable p_ro = prefixes;
				foreach (ListenerPrefix p in p_ro.Keys) {
					string ppath = p.Path;
					if (ppath.Length < best_length)
						continue;

					if (p.Host != host || p.Port != port)
						continue;

					if (path.StartsWith (ppath) || path_slash.StartsWith (ppath)) {
						best_length = ppath.Length;
						best_match = (HttpListener) p_ro [p];
						prefix = p;
					}
				}
				if (best_length != -1)
					return best_match;
			}

			ArrayList list = unhandled;
			best_match = MatchFromList (host, path, list, out prefix);
			if (path != path_slash && best_match == null)
				best_match = MatchFromList (host, path_slash, list, out prefix);
			if (best_match != null)
				return best_match;

			list = all;
			best_match = MatchFromList (host, path, list, out prefix);
			if (path != path_slash && best_match == null)
				best_match = MatchFromList (host, path_slash, list, out prefix);
			if (best_match != null)
				return best_match;

			return null;
		}

		HttpListener MatchFromList (string host, string path, ArrayList list, out ListenerPrefix prefix)
		{
			prefix = null;
			if (list == null)
				return null;

			HttpListener best_match = null;
			int best_length = -1;
			
			foreach (ListenerPrefix p in list) {
				string ppath = p.Path;
				if (ppath.Length < best_length)
					continue;

				if (path.StartsWith (ppath)) {
					best_length = ppath.Length;
					best_match = p.Listener;
					prefix = p;
				}
			}

			return best_match;
		}

		void AddSpecial (ArrayList coll, ListenerPrefix prefix)
		{
			if (coll == null)
				return;

			foreach (ListenerPrefix p in coll) {
				if (p.Path == prefix.Path) //TODO: code
					throw new HttpListenerException (400, "Prefix already in use.");
			}
			coll.Add (prefix);
		}

		bool RemoveSpecial (ArrayList coll, ListenerPrefix prefix)
		{
			if (coll == null)
				return false;

			int c = coll.Count;
			for (int i = 0; i < c; i++) {
				ListenerPrefix p = (ListenerPrefix) coll [i];
				if (p.Path == prefix.Path) {
					coll.RemoveAt (i);
					return true;
				}
			}
			return false;
		}

		void CheckIfRemove ()
		{
			if (prefixes.Count > 0)
				return;

			ArrayList list = unhandled;
			if (list != null && list.Count > 0)
				return;

			list = all;
			if (list != null && list.Count > 0)
				return;

			EndPointManager.RemoveEndPoint (this, endpoint);
		}

		public void Close ()
		{
#if !DNXCORE50
			sock.Close ();
#else
            sock.Dispose();
#endif
            lock (unregistered) {
				//
				// Clone the list because RemoveConnection can be called from Close
				//
				var connections = new List<HttpConnection> (unregistered.Keys);

				foreach (HttpConnection c in connections)
					c.Close (true);
				unregistered.Clear ();
			}
		}

		public void AddPrefix (ListenerPrefix prefix, HttpListener listener)
		{
			ArrayList current;
			ArrayList future;
			if (prefix.Host == "*") {
				do {
					current = unhandled;
					future = (current != null) ? (ArrayList) current.Clone () : new ArrayList ();
					prefix.Listener = listener;
					AddSpecial (future, prefix);
				} while (Interlocked.CompareExchange (ref unhandled, future, current) != current);
				return;
			}

			if (prefix.Host == "+") {
				do {
					current = all;
					future = (current != null) ? (ArrayList) current.Clone () : new ArrayList ();
					prefix.Listener = listener;
					AddSpecial (future, prefix);
				} while (Interlocked.CompareExchange (ref all, future, current) != current);
				return;
			}

			Hashtable prefs, p2;
			do {
				prefs = prefixes;
				if (prefs.ContainsKey (prefix)) {
					HttpListener other = (HttpListener) prefs [prefix];
					if (other != listener) // TODO: code.
						throw new HttpListenerException (400, "There's another listener for " + prefix);
					return;
				}
				p2 = (Hashtable) prefs.Clone ();
				p2 [prefix] = listener;
			} while (Interlocked.CompareExchange (ref prefixes, p2, prefs) != prefs);
		}

		public void RemovePrefix (ListenerPrefix prefix, HttpListener listener)
		{
			ArrayList current;
			ArrayList future;
			if (prefix.Host == "*") {
				do {
					current = unhandled;
					future = (current != null) ? (ArrayList) current.Clone () : new ArrayList ();
					if (!RemoveSpecial (future, prefix))
						break; // Prefix not found
				} while (Interlocked.CompareExchange (ref unhandled, future, current) != current);
				CheckIfRemove ();
				return;
			}

			if (prefix.Host == "+") {
				do {
					current = all;
					future = (current != null) ? (ArrayList) current.Clone () : new ArrayList ();
					if (!RemoveSpecial (future, prefix))
						break; // Prefix not found
				} while (Interlocked.CompareExchange (ref all, future, current) != current);
				CheckIfRemove ();
				return;
			}

			Hashtable prefs, p2;
			do {
				prefs = prefixes;
				if (!prefs.ContainsKey (prefix))
					break;

				p2 = (Hashtable) prefs.Clone ();
				p2.Remove (prefix);
			} while (Interlocked.CompareExchange (ref prefixes, p2, prefs) != prefs);
			CheckIfRemove ();
		}
	}
}
#endif

