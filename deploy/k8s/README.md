# Deploying `fluxvm-kube` as a DaemonSet

Packages the `DisposableVm` CRD + node-local operator (see the root
[README.md](../../README.md)'s "Kubernetes CRD/operator" section) as an
actual Kubernetes workload — this directory is what that section refers to
as "not yet done."

## What this is, and isn't

`fluxvm-kube` never touches the Pod/CRI pipeline: no RuntimeClass, no
containerd shim, no Pod objects created on your behalf. A `DisposableVm` CR
maps 1:1 to a raw VM process on the node named in `spec.node`, driven by a
per-node operator instance talking to a *local* `fluxvm serve` REST API.
This DaemonSet is a straight containerization of that model — one pod per
`fluxvm-capable` node, two containers sharing the pod's network namespace.

## Prerequisites, per node

Before labeling a node `ragnarok.io/fluxvm-capable=true`:

1. **KVM**: `/dev/kvm` present and accessible (virtualization enabled in
   firmware, `kvm`/`kvm_intel`/`kvm_amd` kernel modules loaded).
2. **`nbd` kernel module**: `modprobe nbd` — needed by `guestkit` for image
   customization. This cannot be loaded from inside a container; it's a
   host-level prerequisite, the same way ../../scripts/bootstrap-host.sh
   documents it for the systemd deployment.
3. **VM images pre-staged** under `/var/lib/fluxvm/images` (the
   `state_dir` in configmap.yaml) — there is no k8s-native image pull path
   yet (unlike, e.g., KubeVirt's `containerDisk`). Stage images with the
   same host-prep step that applies the label, or by hand for a first test.
4. A per-node bridge if you intend to use `network_mode: tap` — not
   supported by this CRD yet (see "Known limitations" below); MVP only
   needs step 1-3 for `network_mode: user`.

## Deploy order

```bash
kubectl apply -f namespace.yaml
kubectl apply -f crd.yaml
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl label node <node-name> ragnarok.io/fluxvm-capable=true
kubectl apply -f daemonset.yaml
```

Then verify:

```bash
kubectl -n fluxvm-system get pods -o wide
kubectl -n fluxvm-system logs ds/fluxvm-kube -c fluxvm-kube --follow
```

The `fluxvm-kube` container's logs should show
`starting DisposableVm controller` with `node` equal to the labeled node's
name.

## Smoke test

```bash
kubectl apply -f - <<'EOF'
apiVersion: fluxvm.zyvor.io/v1
kind: DisposableVm
metadata:
  name: smoke-test
  namespace: default
spec:
  node: <node-name>
  backend: qemu
  image: /var/lib/fluxvm/images/<staged-image>.qcow2
  vcpus: 1
  memoryMib: 1024
  networkMode: user
  ttlSeconds: 300
EOF

kubectl get dvm smoke-test -w
```

`phase` should go `Pending` -> `Running` with a `vmId` populated within a
few seconds. Deleting the CR should tear down the VM before the object is
actually removed (finalizer-gated) — `kubectl delete dvm smoke-test` will
appear to hang briefly for exactly that reason, not because it's stuck.

## Rebuilding the CRD manifest

`crd.yaml` is generated, not hand-written:

```bash
cargo run -p fluxvm-kube -- --print-crd > deploy/k8s/crd.yaml
```

Regenerate it whenever `crates/fluxvm-kube/src/crd.rs` changes.

## Known limitations

- **No image distribution**: images must already exist at the given path
  on the target node.
- **Placer is optional**: leave `spec.node` empty only when a
  `fluxvm-kube --enable-placement` instance is running; otherwise pin
  `spec.node` yourself (e.g. from Ragnarok's capable-nodes picker).
- Tap/macvtap with `hostNetwork: true` interact with your CNI — stage
  bridges/parents on the host the same way a bare-metal FluxVM deploy does.
