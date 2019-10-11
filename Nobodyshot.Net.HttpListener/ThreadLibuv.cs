using NetUV.Core.Handles;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nobodyshot.Net
{

    public class ThreadLibuv
    {
        private struct Work
        {
            public Action<object, object> CallbackAdapter;
            public object Callback;
            public object State;
            public TaskCompletionSource<object> Completion;
        }

        private readonly int _maxLoops = 4;

        private readonly TaskCompletionSource<object> _threadTcs = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);


         Loop _loop;
         Async _post;

        private Queue<Work> _workAdding = new Queue<Work>(1024);
        private Queue<Work> _workRunning = new Queue<Work>(1024);
        private Queue<CloseHandle> _closeHandleAdding = new Queue<CloseHandle>(256);
        private Queue<CloseHandle> _closeHandleRunning = new Queue<CloseHandle>(256);

        readonly Thread _thread;

        private readonly object _workSync = new object();
        private readonly object _closeHandleSync = new object();
        private readonly object _startSync = new object();

        IPEndPoint ipEndPoint;

        bool _initCompleted;
        Action<Tcp, Exception> cb_OnConnect;
        public ThreadLibuv(int maxLoops, Action<Tcp,Exception> CallbackOnConnect, IPEndPoint ip)
        {
            _maxLoops = maxLoops;
            _thread = new Thread(ThreadStart);
            _loop = new Loop();
            ipEndPoint = ip;
            this.cb_OnConnect = CallbackOnConnect;
        }

        public Task StartAsync()
        {
            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            _thread.Start(tcs);
            return tcs.Task;
        }
        private void ThreadStart(object parameter)
        {
            lock (_startSync)
            {
                var tcs = (TaskCompletionSource<int>)parameter;
                try
                {

                    _post = _loop.CreateAsync(OnPost);
                    _loop.CreateTcp().SimultaneousAccepts(true).Bind(ipEndPoint).Listen(cb_OnConnect);
                   
                    _initCompleted = true;
                    tcs.SetResult(0);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                    return;
                }
            }

            try
            {
                _loop.RunDefault();
            }
            catch (Exception ex)
            {
            }
            finally
            {
            }
        }

        private void OnPost(Async async)
        {
            var loopsRemaining = _maxLoops;
            bool wasWork;
            do
            {
                wasWork = DoPostWork();
                wasWork = DoPostCloseHandle() || wasWork;

                loopsRemaining--;
            } while (wasWork && loopsRemaining > 0);

        }

        private bool DoPostWork()
        {
            Queue<Work> queue;
            lock (_workSync)
            {
                queue = _workAdding;
                _workAdding = _workRunning;
                _workRunning = queue;
            }

            bool wasWork = queue.Count > 0;

            while (queue.Count != 0)
            {
                var work = queue.Dequeue();
                try
                {
                    work.CallbackAdapter(work.Callback, work.State);
                    work.Completion?.TrySetResult(null);
                }
                catch (Exception ex)
                {
                    if (work.Completion != null)
                    {
                        work.Completion.TrySetException(ex);
                    }
                    else
                    {
                       
                    }
                }
            }

            return wasWork;
        }
        private bool DoPostCloseHandle()
        {
            Queue<CloseHandle> queue;
            lock (_closeHandleSync)
            {
                queue = _closeHandleAdding;
                _closeHandleAdding = _closeHandleRunning;
                _closeHandleRunning = queue;
            }

            bool wasWork = queue.Count > 0;

            while (queue.Count != 0)
            {
                var closeHandle = queue.Dequeue();
                try
                {
                    closeHandle.Callback(closeHandle.Handle);
                }
                catch (Exception ex)
                {
                }
            }

            return wasWork;
        }


        public void Post<T>(Action<T> callback, T state)
        {
            // Handle is closed to don't bother scheduling anything
            if (_post.IsClosing)
            {
                return;
            }

            var work = new Work
            {
                CallbackAdapter = CallbackAdapter<T>.PostCallbackAdapter,
                Callback = callback,
                // TODO: This boxes
                State = state
            };

            lock (_workSync)
            {
                _workAdding.Enqueue(work);
            }

            try
            {
                _post.Send();
            }
            catch (ObjectDisposedException)
            {
                // There's an inherent race here where we're in the middle of shutdown
            }
        }

        public Task PostAsync<T>(Action<T> callback, T state)
        {
            // Handle is closed to don't bother scheduling anything
            if (_post.IsClosing)
            {
                return Task.CompletedTask;
            }

            var tcs = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
            var work = new Work
            {
                CallbackAdapter = CallbackAdapter<T>.PostAsyncCallbackAdapter,
                Callback = callback,
                State = state,
                Completion = tcs
            };

            lock (_workSync)
            {
                _workAdding.Enqueue(work);
            }

            try
            {
                _post.Send();
            }
            catch (ObjectDisposedException)
            {
                // There's an inherent race here where we're in the middle of shutdown
            }
            return tcs.Task;
        }

        private struct CloseHandle
        {
            public Action<IntPtr> Callback;
            public IntPtr Handle;
        }

        private class CallbackAdapter<T>
        {
            public static readonly Action<object, object> PostCallbackAdapter = (callback, state) => ((Action<T>)callback).Invoke((T)state);
            public static readonly Action<object, object> PostAsyncCallbackAdapter = (callback, state) => ((Action<T>)callback).Invoke((T)state);
        }
    }
}
