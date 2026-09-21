#!/bin/bash
# Launch one SEV-SNP guest running the HATLS probe. The SAME tik files passed to two guests model
# re-hosting. Usage: ./launch.sh <name> <zone>
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
NAME="$1"; ZONE="$2"; PROJ=rats-probe
# generate the shared TIK once (reused across guests to model a stolen key)
if [ ! -f tik.key ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out tik.key
  openssl req -x509 -new -key tik.key -days 2 -subj "/CN=hatls-shared-identity" -out tik.crt
fi
STARTUP=$(mktemp)
cat > "$STARTUP" <<'EOS'
#!/bin/bash
exec > /root/startup.log 2>&1; set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq; apt-get install -y -qq python3-openssl python3-cryptography curl
mkdir -p /root
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/tik-key" | base64 -d > /root/guest-tls.key
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/tik-crt" | base64 -d > /root/guest-tls.crt
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/probe" | base64 -d > /root/guest_probe.py
python3 /root/guest_probe.py &
EOS
gcloud compute instances create "$NAME" \
  --project="$PROJ" --zone="$ZONE" --machine-type=n2d-standard-2 \
  --confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --metadata-from-file=startup-script="$STARTUP",tik-key=<(base64 -i tik.key),tik-crt=<(base64 -i tik.crt),probe=<(base64 -i tools/guest_probe.py) \
  --tags=hatls --quiet
rm -f "$STARTUP"
gcloud compute instances describe "$NAME" --zone="$ZONE" --project="$PROJ" \
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
