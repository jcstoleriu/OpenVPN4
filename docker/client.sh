# This script runs in all client containers and serves primarly to generate some network traffic.

# Wait for OpenVPN client to connect.
sleep 10

echo "Generating network traffic.."

ping -c 2 facebook.com

curl -s "https://google.com/" > google.html

curl -s "https://www.google.nl/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png" > logo.png
curl -s "https://www.google.nl/images/searchbox/desktop_searchbox_sprites318_hr.webp" > sprite.webp

ping -c 2 youtube.com

ping -c 3 8.8.8.8

curl -s "https://www.tudelft.nl/" > tudelft.html
