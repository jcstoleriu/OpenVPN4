# This script runs in all client containers and serves primarly to generate some network traffic.

# Wait for OpenVPN client to connect.
sleep 10

echo "Generating network traffic.."

curl -s "https://google.com/" > google.html

ping -c 3 8.8.8.8

curl -s "https://www.tudelft.nl/" > tudelft.html
