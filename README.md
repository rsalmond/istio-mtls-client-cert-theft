# Generating Istio mTLS Client Certs Using Stolen Credentials

Istio service mesh encrypts traffic and validates workload identity using mTLS. In order to populate the sidecar proxies with keys for this use case, the istiod controller contains a certificate authority called citadel, which the sidecar proxies call home to on startup to request client certs. Like many Kubernetes native technologies, access to citadel requires the caller to present a valid Kubernetes service account token. No token, no mTLS client cert.

It is well understood in many contexts that security account tokens should be protected, but (in my experience) it does not seem to be well understood that access to a security account token == ability to spoof identity in the service mesh.

This repo demonstrates the situation.

### Test Setup

The setup contains two namespaces. In the secure namespace is a deployment and service called "victim", and a deployment called "legitclient". An Istio `PeerAuthentication` resource requires all traffic bound for pods in this namespace to be mTLS encrypted (cleartext traffic will be rejected by the sidecar proxies on these pods) and an Istio `AuthorizationPolicy` requires all traffic destined for the "victim" workloads to be identified by the SPIFFE identity `spiffee://cluster.local/ns/secure/sa/legitclient`, which can be read as "this request is coming from the 'secure' namespace and the requesting pod is using the 'legitclient' Kubernetes service account". See [secure.yaml](secure.yaml) and references below for specifics.

![x](foo.png)

### Running The Test

#### Requirements
- a running cluster / valid kubeconfig
- `istioctl install -y` (tested on 1.14 - 1.16)
- openssl
- jq
- [grpcurl](https://github.com/fullstorydev/grpcurl)


#### Do it already!

``` console
$ ./run.sh
 ==  deleting previously generated key and signing request
 ==  deleting previously stolen client cert
 ==  generating a random key and signing request
Generating a 2048 bit RSA private key
..................................+++++
.....................................................................................................................................................................................+++++
writing new private key to 'istio-attack.key'
-----
 ==  'stealing' the service account token from the sidecar proxy of a legit client pod
Forwarding from 127.0.0.1:15012 -> 15012
Forwarding from [::1]:15012 -> 15012
 ==  using service account "legitclient" in namespace "secure" to ask istiod/citadel for a client cert
Handling connection for 15012
./run.sh: line 43: 92868 Terminated: 15          kubectl port-forward svc/istiod -n istio-system 15012:15012
 ==  confirmed that the modulus of our private key matches the modulus of our stolen cert
 ==  istiod has successfully issued us an mTLS client cert!
 ==  copying private key and stolen client cert into attack pod
 ==  attempting to connect to victim service from the attack pod without using stolen credentials
 ==  (we expect connection will fail: reset by peer)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (56) Recv failure: Connection reset by peer
command terminated with exit code 56

 ==  attempting to connect to victim service from the attack pod using stolen credentials
 ==  (we expect connection will succeed)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0{
  "headers": {
    "Accept": "*/*",
    "Host": "victim.secure:80",
    "User-Agent": "curl/7.68.0",
    "X-B3-Sampled": "1",
    "X-B3-Spanid": "84f811a00cada672",
    "X-B3-Traceid": "729bc7a2f7786adb84f811a00cada672",
    "X-Forwarded-Client-Cert": "By=spiffe://cluster.local/ns/secure/sa/default;Hash=08e34416bbb9cdcbf0fe6f83c123f664cd4c9b5bfabd1eea558a80a307f1abad;Subject=\"\";URI=spiffe://cluster.local/ns/secure/sa/legitclient"
  }
}
100   450  100   450    0     0  21428      0 --:--:-- --:--:-- --:--:-- 21428
```

#### What is happening?

When the script executed the following steps will take place:
1. a new private key and certificate signing request will be generated
1. the service account token from the sidecar container of the legitclient pod will be "stolen"
1. the stolen service account token will be used to send the csr to istiod/citadel asking for a signed mTLS client certificate
1. citadel will accept the stolen token and sign the csr, returning an mTLS client certificate with the identity data populated by the claims present in the stolen token
1. we will attempt to plaintext curl the victim service from within the attack pod in the attack namespace, since mTLS is required this connection will be rejected by the receiving sidecar proxy on the victim pod (reset by peer)
1. we will attempt to curl the victim service from within the attack pod in the attack namespace, but this time using the private key and signed client certificate, which will be authenticated by the receiving sidecar proxy on the victim pod, and a connection established using the identity of the legitclient in the secure namespace.

Note that upon successful authentication of a valid inbound mTLS connection, the istio-proxy will populate an HTTP response header called `X-Forwarded-Client-Cert` (or "XFCC") with both the receiving / server side identity (indicated with "By=spiffe...") and the sending / client side identity (indicated with "URI=spiffe..."). By examining this header you can verify that the connection was established using the stolen identity.

### References

https://istio.io/latest/docs/reference/config/security/authorization-policy/#Source
https://github.com/istio/istio/blob/master/pkg/istio-agent/README.md
https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
