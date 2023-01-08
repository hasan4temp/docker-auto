#/bin/bash
docker kill $(docker ps -q)
docker rm $(docker ps -a -q)
docker rmi $(docker images -q)
docker volume prune -f
docker system prune -a -f

file_name=$(date +%Y-%m-%d-T%H-%M-%S)

mv /home/mariadb_storage/data /home/mariadb_storage/$file_name