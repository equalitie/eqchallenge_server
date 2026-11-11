# Public demo on Kubernetes

For showing the demo to people outside localhost. It needs HTTPS (the widget refuses to run
outside a secure context), so it goes behind an ingress with a certificate.

The manifest has placeholders; fill them from your shell, never commit the values:

```sh
export NAMESPACE=eqchallenge-demo
export IMAGE=<registry>/eqchallenge-demo:<tag>
export HOST=<demo hostname, with a DNS record pointing at the ingress>
export INGRESS_CLASS=<ingress class, e.g. nginx>
export CLUSTER_ISSUER=<cert-manager ClusterIssuer>

docker buildx build --platform linux/amd64 -t "$IMAGE" --push .

kubectl apply -f <(envsubst < k8s/demo.yaml)
kubectl -n "$NAMESPACE" create secret generic eqchallenge-demo \
  --from-literal=secret="$(openssl rand -base64 32)"
kubectl -n "$NAMESPACE" rollout status deploy/eqchallenge-demo
```

Notes:
- One replica: attempts and used challenges are kept in memory.
- `EQC_CLIENT_IP_HEADER=X-Real-IP` binds passes to the visitor, not to the ingress pod. Check
  after deploying that the ingress sees real client IPs (an external load balancer may
  hide them); otherwise all visitors share one binding.
- The public demo shows visitors their behaviour features but does not record them.
- Remove it with `kubectl delete namespace "$NAMESPACE"`.
