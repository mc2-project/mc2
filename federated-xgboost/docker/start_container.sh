docker container stop sec-xgb
docker container rm sec-xgb

docker image build -t xgb:latest .

docker run -it -m 4g -v `pwd`/../../:/root/mc2 -w /root/ -p 9000-9100:9000-9100 --name sec-xgb xgb:latest
