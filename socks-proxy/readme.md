docker run -e USERNAME=admin -e PASSWORD=admin -e PORT=1090 -p 1090:1090 mehdi4691/socks-gen:1.0.0
docker run -e USERNAME=test -e PASSWORD=test -e PORT=1080 -p 1080:1080 -d --name test mehdi4691/socks-gen:1.0.0