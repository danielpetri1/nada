use boring::{error::ErrorStack, ssl::SslContextBuilder};
use std::sync::{Arc, Mutex};
use tokio_quiche::{
    quic::ConnectionHook,
    settings::{CertificateKind, TlsCertificatePaths},
    ConnectionParams,
};

struct TlsContext(Mutex<Option<SslContextBuilder>>);

impl ConnectionHook for TlsContext {
    fn create_custom_ssl_context_builder(
        &self,
        _: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        self.0.lock().ok()?.take()
    }
}

pub(crate) fn configure_tls(
    params: &mut ConnectionParams<'_>,
    mut builder: SslContextBuilder,
    curves: &str,
) -> Result<(), ErrorStack> {
    builder.set_curves_list(curves)?;
    // tokio-quiche invokes the context hook only when TLS paths are present.
    // Client contexts supply trust roots directly and need no certificate paths.
    params.tls_cert.get_or_insert(TlsCertificatePaths {
        cert: "",
        private_key: "",
        kind: CertificateKind::X509,
    });
    params.hooks.connection_hook = Some(Arc::new(TlsContext(Mutex::new(Some(builder)))));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{Ssl, SslMethod, SslStream};
    use octets::Octets;
    use std::io::Cursor;

    fn advertised_groups(curves: &str) -> Vec<u16> {
        let mut params = ConnectionParams::default();
        let builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
        configure_tls(&mut params, builder, curves).unwrap();
        let builder = params
            .hooks
            .connection_hook
            .as_ref()
            .unwrap()
            .create_custom_ssl_context_builder(params.tls_cert.unwrap())
            .unwrap();
        let ssl = Ssl::new(&builder.build()).unwrap();
        let mut stream = SslStream::new(ssl, Cursor::new(Vec::new())).unwrap();
        // Capture the ClientHello. The empty input ends the handshake before a reply.
        assert!(stream.connect().is_err());

        let mut record = Octets::with_slice(stream.get_ref().get_ref());
        assert_eq!(record.get_u8().unwrap(), 22); // Handshake record.
        record.skip(2).unwrap(); // Legacy record version.
        let mut handshake = record.get_bytes_with_u16_length().unwrap();
        assert_eq!(handshake.get_u8().unwrap(), 1); // ClientHello.
        let len = handshake.get_u24().unwrap() as usize;
        let mut hello = handshake.get_bytes(len).unwrap();
        hello.skip(34).unwrap(); // Legacy version and random.
        hello.get_bytes_with_u8_length().unwrap(); // Session ID.
        hello.get_bytes_with_u16_length().unwrap(); // Cipher suites.
        hello.get_bytes_with_u8_length().unwrap(); // Compression methods.
        let mut extensions = hello.get_bytes_with_u16_length().unwrap();
        while extensions.cap() > 0 {
            let kind = extensions.get_u16().unwrap();
            let mut extension = extensions.get_bytes_with_u16_length().unwrap();
            if kind == 10 {
                let mut groups = extension.get_bytes_with_u16_length().unwrap();
                let mut advertised = Vec::new();
                while groups.cap() > 0 {
                    advertised.push(groups.get_u16().unwrap());
                }
                return advertised;
            }
        }
        panic!("ClientHello has no supported_groups extension");
    }

    #[test]
    fn context_advertises_only_the_configured_groups() {
        assert_eq!(
            advertised_groups(crate::DEFAULT_TLS_CURVES_LIST),
            [0x11ec, 0x001d, 0x0017, 0x0018]
        );
        assert_eq!(advertised_groups("X25519MLKEM768"), [0x11ec]);
        assert_eq!(advertised_groups("X25519:P-256"), [0x001d, 0x0017]);
    }

    #[test]
    fn invalid_groups_are_rejected_without_installing_a_context() {
        for curves in ["", "invalid", "X25519MLKEM768:invalid", "X25519\0"] {
            let mut params = ConnectionParams::default();
            let builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
            assert!(configure_tls(&mut params, builder, curves).is_err());
            assert!(params.hooks.connection_hook.is_none());
        }
    }
}
