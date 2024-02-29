#!/bin/bash

# Remove old configuration
rm -rf openvpn-data

# Create new server configuration and certificates
docker-compose run --rm openvpn ovpn_genconfig -u udp://VPN.SERVERNAME.COM
printf "okay\nokay\n\nokay\okay" | docker-compose run --rm openvpn ovpn_initpki nopass

# Start the server
docker-compose up -d openvpn

# Generate a client certificate and get the configuration
CLIENTNAME="client"
docker-compose run --rm openvpn easyrsa build-client-full $CLIENTNAME nopass
docker-compose run --rm openvpn ovpn_getclient $CLIENTNAME > $CLIENTNAME.ovpn

# Get the local server IP
openvpn_server_address=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' openvpn)

# Replace the server address in the client configuration to use the local server IP
sed -i "s/VPN.SERVERNAME.COM/$openvpn_server_address/g" client.ovpn

echo "Your client config is available at $CLIENTNAME.ovpn"
echo "Your server IP is $openvpn_server_address"
echo "You can now connect to the server using: openvpn --config $CLIENTNAME.ovpn"