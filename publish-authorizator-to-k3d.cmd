call update-version
call npm run build

kubectl delete -f test\sample.yaml
kubectl delete deployment obk-authorizator-ja-jfvilas-deply -n dev
kubectl delete service  obk-authorizator-ja-jfvilas-svc -n dev

docker image rm obk-authorizator:latest
docker build . -t obk-authorizator
call k3d image import obk-authorizator:latest -t -c oberkorn
kubectl apply -f test\sample.yaml
