call npm run build
set /p major=<major
set /p minor=<minor
set /p level=<level
set currversion=%major%.%minor%.%level%
set /a level=%level%+1
echo %level% > level
set nextversion=%major%.%minor%.%level%
echo %currversion% to %nextversion%
docker image rm obk-authorizator:latest
docker build . -t obk-authorizator -t jfvilasoutlook/obk-authorizator:%nextversion% -t jfvilasoutlook/obk-authorizator:latest
docker push jfvilasoutlook/obk-authorizator:%nextversion%
docker push jfvilasoutlook/obk-authorizator:latest
