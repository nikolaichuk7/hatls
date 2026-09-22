#!/bin/bash
# A resumed TLS 1.3 handshake has no Certificate message -- so no carrier for the remoteAttestation
# extension of draft-fossati-seat-early-attestation-07 Section 4.1 -- and with 0-RTT the application
# data is delivered before the server has sent anything at all.
#
# Needs: openssl 3.x on PATH. Everything is local (127.0.0.1); nothing leaves the machine.
# Usage:  bash examples/resumption.sh [port]
set -u
PORT=${1:-14537}
D=$(mktemp -d); cd "$D"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.crt \
        -days 1 -subj "/CN=resumption-experiment" 2>/dev/null
printf 'GET /secret HTTP/1.1\r\nHost: x\r\n\r\n' > early.txt
# no -www: OpenSSL 3.0.x refuses "-early_data in combination with -www" (3.6 allows it). Without
# -www the server reads its stdin; in the background that is EOF, and in TLS 1.3 SSL_accept()
# returns before the client's Finished arrives, so the server would shut the connection down
# right after its own Finished. A stdin that stays open for the run keeps it serving.
sleep 30 2>/dev/null | openssl s_server -cert srv.crt -key srv.key -tls1_3 -accept "$PORT" -early_data -naccept 2 -msg > srv.log 2>&1 &
SLEEPPID=$(jobs -p | head -1)
SRVPID=$!
for i in $(seq 1 30); do
  if grep -q "^ACCEPT" srv.log 2>/dev/null; then break; fi
  if ! kill -0 "$SRVPID" 2>/dev/null; then echo "s_server exited early:"; cat srv.log; exit 1; fi
  sleep 0.2
done
grep -q "^ACCEPT" srv.log || { echo "s_server did not start listening:"; cat srv.log; kill "$SRVPID" 2>/dev/null; exit 1; }
echo "openssl: $(openssl version)"
echo
echo "--- connection 1: full handshake, obtain a session ticket ---"
(printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1.5) | openssl s_client -connect 127.0.0.1:"$PORT" -tls1_3 -sess_out sess.pem 2>&1 | grep -E "^(New|Reused), |Early data"
echo
echo "--- connection 2: resume, and send 0-RTT early data ---"
(sleep 1.5) | openssl s_client -connect 127.0.0.1:"$PORT" -tls1_3 -sess_in sess.pem -early_data early.txt 2>&1 | grep -E "^(New|Reused), |Early data"
sleep 1; kill "$SRVPID" "$SLEEPPID" 2>/dev/null; wait 2>/dev/null
grep -q "ClientHello" srv.log || { echo "the server saw no handshake at all; its log:"; cat srv.log; exit 1; }
msgs() { awk -v want="$1" '/ClientHello/{n++} n==want' srv.log | grep -oE "(>>>|<<<) TLS 1.3, Handshake \[length [0-9a-f]+\], [A-Za-z]+" | sed -E 's/\[length [0-9a-f]+\], //; s/>>> TLS 1.3, Handshake/  server sends  /; s/<<< TLS 1.3, Handshake/  server gets   /'; }
echo
echo "--- handshake messages, connection 1 (full) ---";    msgs 1
echo
echo "--- handshake messages, connection 2 (resumed) ---"; msgs 2
# count the Certificate message itself, not CertificateVerify or CertificateRequest
cnt() { msgs "$1" | grep -cE "Certificate$"; }
echo
echo "--- Certificate messages (exactly that message) per handshake ---"
echo "  connection 1 (full):    $(cnt 1)"
echo "  connection 2 (resumed): $(cnt 2)"
echo
echo "The extension of Section 4.1 lives in the Certificate message. In the resumed handshake there is none."
cd /; rm -rf "$D"
