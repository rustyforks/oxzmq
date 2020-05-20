/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::{
    frame::{Frame, FrameParseError, MessageFrame},
    handshake::{Handshake, HandshakeError},
    socket::{SocketType, SocketTypeFromBytesError},
};
use futures::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::{convert::TryFrom, marker::Unpin};

mod frame;
mod handshake;
mod parse;
mod socket;

const PADDING_LEN: usize = 8;
const FILLER_LEN: usize = 31;

#[derive(Debug, Clone)]
pub struct ZmtpSocket<S> {
    connections: Vec<Connection<S>>,
    socket_type: SocketType,
}

#[derive(Debug, Clone)]
pub struct Connection<S> {
    remote_version: Version,
    handshake: Handshake,
    remote_socket_type: SocketType,
    multipart_buffer: Vec<MessageFrame>,
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub async fn new(
        mut stream: S,
        mechanism: Mechanism,
        socket_type: SocketType,
    ) -> Result<Connection<S>, ConnectionError> {
        // Send a greeting to the remote peer.
        Greeting::write_to(mechanism, &mut stream).await?;

        // Receive a greeting and check for validity.
        let greeting = Greeting::read_new(&mut stream).await?;
        let remote_version = greeting.version;

        if !remote_version.supported() {
            let err_cmd = Frame::new_fatal_error("ZMTP version not supported");
            err_cmd.write_to(&mut stream).await?;
            return Err(ConnectionError::RemoteVersionNotSupported(remote_version));
        }

        // Perform a handshake to determine how the peers will talk going forward
        // and what secrets to store for the peer, if any (e.g. cryptographic keys).
        let handshake = Handshake::perform(&mut stream, &greeting, &socket_type).await?;

        let remote_socket_type_bytes = match &handshake {
            Handshake::Null(null_handshake) => null_handshake
                .properties
                .get(String::from("socket-type"))
                .map(|slice| slice.to_vec()),
        };
        let remote_socket_type_bytes =
            remote_socket_type_bytes.ok_or(ConnectionError::MissingRemoteSocketType)?;
        let remote_socket_type = SocketType::try_from(remote_socket_type_bytes.as_slice())?;

        // Check if the socket types are a valid combination.
        if !socket_type.valid_socket_combo(&remote_socket_type) {
            let err_cmd = Frame::new_fatal_error("invalid socket combination");
            err_cmd.write_to(&mut stream).await?;
            return Err(ConnectionError::InvalidSocketCombination(
                socket_type,
                remote_socket_type,
            ));
        }

        Ok(Self {
            remote_version,
            handshake,
            remote_socket_type,
            multipart_buffer: Vec::new(),
            stream,
        })
    }

    pub async fn recv_frame(&mut self) -> Result<Frame, RecvFrameError> {
        match self.handshake {
            Handshake::Null(_) => Ok(Frame::read_new(&mut self.stream).await?),
        }
    }

    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), io::Error> {
        match self.handshake {
            Handshake::Null(_) => {
                frame.write_to(&mut self.stream).await?;
                Ok(())
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectionError {
    #[error("error reading data stream")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Greeting(#[from] GreetingError),

    #[error("error in handshake")]
    Handshake(#[from] HandshakeError),

    #[error("invalid remote socket type")]
    UnsupportedRemoteSocketType(#[from] SocketTypeFromBytesError),

    #[error("invalid socket combination: {:?} with {:?}", .0, .1)]
    InvalidSocketCombination(SocketType, SocketType),

    #[error("remote peer must provide socket type")]
    MissingRemoteSocketType,

    #[error("remote version ({}.{}) not supported", .0.major, .0.minor)]
    RemoteVersionNotSupported(Version),
}

#[derive(thiserror::Error, Debug)]
pub enum RecvFrameError {
    #[error("error reading data stream")]
    Io(#[from] io::Error),

    #[error("could not parse frame")]
    MalformedFrame(#[from] FrameParseError),
}

#[derive(Debug, Clone)]
struct Greeting {
    version: Version,
    mechanism: Mechanism,
    as_server: AsServer,
}

impl Greeting {
    pub async fn read_new<R>(stream: &mut R) -> Result<Greeting, GreetingError>
    where
        R: AsyncRead + Unpin,
    {
        // Read whole greeting as a chunk of bytes, then parse it.
        let mut greeting_bytes = Vec::with_capacity(64);
        stream.read_exact(&mut greeting_bytes).await?;
        drop(stream); // make sure we don't read from it again

        let rest = greeting_bytes.as_slice();

        // Read signature bytes separated by padding.
        let (sig_first_byte, rest) = parse::parse_u8(rest);
        let rest = &rest[PADDING_LEN..]; // discard padding
        let (sig_last_byte, rest) = parse::parse_u8(rest);

        if sig_first_byte != 0xFF {
            return Err(GreetingError::Signature);
        }

        if sig_last_byte != 0x7F {
            return Err(GreetingError::Signature);
        }

        // Read version
        let (version_major, rest) = parse::parse_u8(rest);
        let (version_minor, rest) = parse::parse_u8(rest);

        let version = Version {
            major: version_major,
            minor: version_minor,
        };

        // Read mechanism
        let mechanism_buf = &rest[..20];
        let rest = &rest[20..];
        let null_idx = mechanism_buf
            .iter()
            .position(|&x| x == 0x00)
            .unwrap_or(mechanism_buf.len());
        let mechanism_str = std::str::from_utf8(&mechanism_buf[..null_idx])?;
        if mechanism_str.chars().any(|c| {
            c.is_lowercase() || !(c.is_alphanumeric() || ['-', '_', '.', '+'].contains(&c))
        }) {
            return Err(GreetingError::MechanismInvalidChar);
        }
        let mechanism = match mechanism_str {
            "NULL" => Mechanism::Null,
            _ => return Err(GreetingError::MechanismUnsupported),
        };

        // Read as-server
        let (as_server_byte, _) = parse::parse_u8(rest);
        let as_server = match as_server_byte {
            0x00 => AsServer::Client,
            0x01 => AsServer::Server,
            x => return Err(GreetingError::AsServer(x)),
        };

        Ok(Self {
            version,
            mechanism,
            as_server,
        })
    }

    pub async fn write_to<W>(mechanism: Mechanism, stream: &mut W) -> Result<(), io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut greeting_buffer = Vec::<u8>::with_capacity(64);

        // Write signature.
        greeting_buffer.push(0xFF);
        greeting_buffer.extend(std::iter::repeat(0x00).take(PADDING_LEN));
        greeting_buffer.push(0x7F);

        // Write version.
        greeting_buffer.extend_from_slice(&[0x03, 0x00]);

        // Write mechanism.
        mechanism.write_to(&mut greeting_buffer).await?;

        // Write as-server.
        match mechanism {
            Mechanism::Null => greeting_buffer.push(0),
        }

        // Write filler.
        greeting_buffer.extend(std::iter::repeat(0x00).take(FILLER_LEN));

        stream.write_all(&greeting_buffer).await?;
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GreetingError {
    #[error("error reading data stream")]
    Io(#[from] io::Error),

    #[error("malformed signature")]
    Signature,

    #[error("unsupported version: {0:?}")]
    Version(Version),

    #[error("mechanism not utf8: {0}")]
    MechanismNotUtf8(#[from] std::str::Utf8Error),

    #[error("invalid character in mechanism string")]
    MechanismInvalidChar,

    #[error("mechanism string not supported")]
    MechanismUnsupported,

    #[error("invalid as-server value: {0}")]
    AsServer(u8),
}

/// `Version` can be returned as part of an error in `GreetingError`. It
/// might be helpful for downstream crates to use this information.
#[derive(Debug, Clone, Copy)]
pub struct Version {
    major: u8,
    minor: u8,
}

impl Version {
    pub fn supported(&self) -> bool {
        self.major >= 3
    }
}

#[derive(Debug, Clone)]
pub enum Mechanism {
    Null,
}

impl Mechanism {
    pub async fn write_to<W>(&self, stream: &mut W) -> Result<(), io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mechanism_str = match self {
            Mechanism::Null => "NULL",
        };

        stream.write_all(mechanism_str.as_bytes()).await?;
        stream.write_all(&[0; 20][mechanism_str.len()..]).await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
enum AsServer {
    Server,
    Client,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::Async;

    #[test]
    fn connect_null() {
        let (local, remote) = tcp_test::channel();
        let local = Async::new(local);
        let remote = Async::new(remote);

        let local_conn = Connection::new(local, Mechanism::Null, SocketType::Req);
        let remote_conn = Connection::new(remote, Mechanism::Null, SocketType::Req);

        smol::run(async move {})
    }
}
