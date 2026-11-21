#!/usr/bin/env bash
# Build, push and deploy privnet to the xuno cluster.
#
#   deploy/deploy.sh            # build + push image tagged with the git sha, then apply
#   SKIP_BUILD=1 deploy/deploy.sh
#
# Env overrides: KUBE_CONTEXT, NAMESPACE, IMAGE_REPO, TAG
set -euo pipefail

cd "$(dirname "$0")/.."
KUBE_CONTEXT=${KUBE_CONTEXT:-xuno-admin@xuno}
NAMESPACE=${NAMESPACE:-privnet}
IMAGE_REPO=${IMAGE_REPO:-docker.io/dameyerdave/privnet}
TAG=${TAG:-$(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)}
K="kubectl --context $KUBE_CONTEXT -n $NAMESPACE"
DIR=deploy/k8s

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "==> building $IMAGE_REPO:$TAG (linux/amd64)"
  docker buildx build --platform linux/amd64 -t "$IMAGE_REPO:$TAG" --push .
fi

kubectl --context "$KUBE_CONTEXT" apply -f $DIR/namespace.yaml

# The app secret encrypts device keys at rest. Reuse the one already in the
# cluster: generating a new one would make stored keys unreadable.
if [[ ! -s $DIR/secret.env ]]; then
  existing=$($K get secret -l app.kubernetes.io/part-of=privnet -o jsonpath='{.items[0].data.APP_SECRET}' 2>/dev/null || true)
  if [[ -n "$existing" ]]; then
    echo "APP_SECRET=$(echo "$existing" | base64 -d)" > $DIR/secret.env
  else
    echo "APP_SECRET=$(openssl rand -hex 32)" > $DIR/secret.env
  fi
  chmod 600 $DIR/secret.env
fi

echo "==> ensuring WireGuard load balancer"
$K apply -f $DIR/service.yaml
for i in $(seq 1 60); do
  ip=$($K get svc privnet-wg -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
  [[ -n "$ip" ]] && break
  sleep 5
done
[[ -n "$ip" ]] || { echo "load balancer has no external IP yet" >&2; exit 1; }
port=$($K get svc privnet-wg -o jsonpath='{.spec.ports[0].port}')
sed -i.bak "s|^WG_ENDPOINT=.*|WG_ENDPOINT=$ip:$port|" $DIR/config.env && rm -f $DIR/config.env.bak
echo "    endpoint: $ip:$port/udp"
for i in $(seq 1 60); do
  dnsip=$($K get svc privnet-dns -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
  [[ -n "$dnsip" ]] && break
  sleep 5
done
[[ -n "$dnsip" ]] || { echo "DNS load balancer has no external IP yet" >&2; exit 1; }
sed -i.bak "s|^DNS_PUBLIC_IP=.*|DNS_PUBLIC_IP=$dnsip|" $DIR/config.env && rm -f $DIR/config.env.bak
echo "    dns: $dnsip:53 (udp+tcp)"

sed -i.bak -E "s|^(    newName: ).*|\1$IMAGE_REPO|; s|^(    newTag: ).*|\1$TAG|" $DIR/kustomization.yaml && rm -f $DIR/kustomization.yaml.bak

echo "==> applying manifests"
kubectl --context "$KUBE_CONTEXT" apply -k $DIR
$K rollout status deploy/privnet --timeout=180s
echo "==> done: https://privnet.kizy.ch  (WireGuard $ip:$port/udp)"
