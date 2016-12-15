/*
 * Copyright (C) 2016 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Deque;
import java.util.concurrent.LinkedBlockingDeque;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import okhttp3.DelegatingSSLSocket;
import okio.Buffer;
import okio.ByteString;

/** Records all bytes transmitted over a socket and makes them available for inspection. */
public final class SocketRecorder {
  private final Deque<Conversation> conversations = new LinkedBlockingDeque<>();

  /** Returns an SSLSocketFactory whose sockets will record all transmitted bytes. */
  public SSLSocketFactory sslSocketFactory(SSLSocketFactory delegate) {
    return new RecordingSslSocketFactory(delegate);
  }

  /** Returns a SocketFactory whose sockets will record all transmitted bytes. */
  public SocketFactory socketFactory(SocketFactory delegate) {
    return null; // TODO
  }

  public Conversation takeConversation() {
    return conversations.remove();
  }

  /** A bidirectional transfer of unadulterated bytes over a socket. */
  public static final class Conversation {
    private final Buffer bytesSentFromClient = new Buffer();
    private final Buffer bytesSentFromServer = new Buffer();

    synchronized void byteSentFromClient(int b) {
      bytesSentFromClient.writeByte(b);
    }

    synchronized void byteSentFromServer(int b) {
      bytesSentFromServer.writeByte(b);
    }

    synchronized void bytesSentFromClient(byte[] bytes, int offset, int length) {
      bytesSentFromClient.write(bytes, offset, length);
    }

    synchronized void bytesSentFromServer(byte[] bytes, int offset, int length) {
      bytesSentFromServer.write(bytes, offset, length);
    }

    public synchronized ByteString bytesSentFromClient() {
      return bytesSentFromClient.readByteString();
    }

    public synchronized ByteString bytesSentFromServer() {
      return bytesSentFromServer.readByteString();
    }
  }

  /** Records the bytes read from the socket. These will be from the server. */
  static final class RecordingInputStream extends InputStream {
    private final Socket socket;
    private final Conversation conversation;

    RecordingInputStream(Socket socket, Conversation conversation) {
      this.socket = socket;
      this.conversation = conversation;
    }

    @Override public int read() throws IOException {
      int b = socket.getInputStream().read();
      if (b == -1) return -1;
      conversation.byteSentFromServer(b);
      return b;
    }

    @Override public int read(byte[] b, int off, int len) throws IOException {
      int read = socket.getInputStream().read(b, off, len);
      if (read == -1) return -1;
      conversation.bytesSentFromServer(b, off, read);
      return read;
    }

    @Override public void close() throws IOException {
      socket.getInputStream().close();
    }
  }

  /** Records the bytes written to the socket. These will be from the client. */
  static final class RecordingOutputStream extends OutputStream {
    private final Socket socket;
    private final Conversation conversation;

    RecordingOutputStream(Socket socket, Conversation conversation) {
      this.socket = socket;
      this.conversation = conversation;
    }

    @Override public void write(int b) throws IOException {
      socket.getOutputStream().write(b);
      conversation.byteSentFromClient(b);
    }

    @Override public void write(byte[] b, int off, int len) throws IOException {
      socket.getOutputStream().write(b, off, len);
      conversation.bytesSentFromClient(b, off, len);
    }

    @Override public void close() throws IOException {
      socket.getOutputStream().close();
    }

    @Override public void flush() throws IOException {
      socket.getOutputStream().flush();
    }
  }

  final class SSLSocketRecorder extends DelegatingSSLSocket {
    private final InputStream inputStream;
    private final OutputStream outputStream;

    SSLSocketRecorder(SSLSocket delegate, Conversation conversation) {
      super(delegate);
      inputStream = new RecordingInputStream(delegate, conversation);
      outputStream = new RecordingOutputStream(delegate, conversation);
    }

    /**
     * Intercept the handshake to configure TLS extensions to properly configure Jetty ALPN. Jetty
     * ALPN expects the real SSLSocket to be placed in the global map. Because we are wrapping the
     * real SSLSocket, it confuses Jetty ALPN. This patches that up so things work as expected.
     */
    @Override public void startHandshake() throws IOException {
      Class<?> alpn = null;
      Class<?> provider = null;
      try {
        alpn = Class.forName("org.eclipse.jetty.alpn.ALPN");
        provider = Class.forName("org.eclipse.jetty.alpn.ALPN$Provider");
      } catch (ClassNotFoundException ignored) {
      }

      if (alpn == null || provider == null) {
        // No Jetty, so nothing to worry about.
        super.startHandshake();
        return;
      }

      Object providerInstance = null;
      Method putMethod = null;
      try {
        Method getMethod = alpn.getMethod("get", SSLSocket.class);
        putMethod = alpn.getMethod("put", SSLSocket.class, provider);
        providerInstance = getMethod.invoke(null, this);
        if (providerInstance == null) {
          // Jetty's on the classpath but TLS extensions weren't used.
          super.startHandshake();
          return;
        }

        // Replace with the real SSLSocket to make Jetty ALPN happy.
        putMethod.invoke(null, delegate, providerInstance);
        super.startHandshake();
      } catch (ReflectiveOperationException e) {
        throw new AssertionError();
      } finally {
        // If we replaced the SSLSocket, we must put the original back for everything to work within
        // OkHttp.
        if (providerInstance != null) {
          try {
            putMethod.invoke(null, this, providerInstance);
          } catch (ReflectiveOperationException e) {
            throw new AssertionError();
          }
        }
      }
    }

    @Override public InputStream getInputStream() throws IOException {
      return inputStream;
    }

    @Override public OutputStream getOutputStream() throws IOException {
      return outputStream;
    }
  }

  /** Creates SSLSockets whose bytes will be recorded. */
  final class RecordingSslSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;

    RecordingSslSocketFactory(SSLSocketFactory delegate) {
      this.delegate = delegate;
    }

    @Override public String[] getDefaultCipherSuites() {
      return delegate.getDefaultCipherSuites();
    }

    @Override public String[] getSupportedCipherSuites() {
      return delegate.getSupportedCipherSuites();
    }

    @Override public Socket createSocket(Socket socket, String hostname, int port, boolean b)
        throws IOException {
      SSLSocket sslSocket = (SSLSocket) delegate.createSocket(socket, hostname, port, b);
      return newSocket(sslSocket);
    }

    private Socket newSocket(SSLSocket sslSocket) {
      Conversation conversation = new Conversation();
      conversations.add(conversation);
      SSLSocketRecorder sslSocketRecorder = new SSLSocketRecorder(sslSocket, conversation);
      return sslSocketRecorder;
    }

    @Override public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
      SSLSocket sslSocket = (SSLSocket) delegate.createSocket(s, i);
      return newSocket(sslSocket);
    }

    @Override public Socket createSocket(String s, int i, InetAddress inetAddress, int i1)
        throws IOException, UnknownHostException {
      SSLSocket sslSocket = (SSLSocket) delegate.createSocket(s, i, inetAddress, i1);
      return newSocket(sslSocket);
    }

    @Override public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
      SSLSocket sslSocket = (SSLSocket) delegate.createSocket(inetAddress, i);
      return newSocket(sslSocket);
    }

    @Override public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1,
        int i1) throws IOException {
      SSLSocket sslSocket = (SSLSocket) delegate.createSocket(inetAddress, i, inetAddress1, i1);
      return newSocket(sslSocket);
    }
  }
}
