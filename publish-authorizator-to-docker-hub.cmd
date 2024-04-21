call npm run build
set /p major=<major
set /p minor=<minor
set /p level=<level
set currversion=%major%.%minor%.%level%
docker image rm obk-authorizator:latest
docker build . -t obk-authorizator -t jfvilasoutlook/obk-authorizator:%currentversion% -t jfvilasoutlook/obk-authorizator:latest
docker push jfvilasoutlook/obk-authorizator:%currentversion%
docker push jfvilasoutlook/obk-authorizator:latest
