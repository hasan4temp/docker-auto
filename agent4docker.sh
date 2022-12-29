#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

function sed_rt() {
  echo "$1" | sed -e 's/^ *//g' -e 's/ *$//g' | sed -n '1 p'
}

function to_base64() {
  #echo "$1" | base64 
  echo "$1" | tr -d '\n' | base64 | tr -d '=' | tr -d '\n' | sed 's/\//%2F/g' | sed 's/\+/%2B/g'
}

function to_int() {
  echo ${1/\.*/}
}

function to_num() {
  case $1 in
  '' | *[!0-9\.]*) echo 0 ;;
  *) echo $1 ;;
  esac
}

version=$(sed_rt "$version")

#uptime=$(sed_rt $(to_int "$(cat /proc/uptime | awk '{ print $1 }')"))
uptime=$(uptime -p)

sessions=$(sed_rt "$(who | wc -l)")

processes=$(sed_rt "$(ps axc | wc -l)")

processes_list="$(ps axc -o uname:12,pcpu,rss,cmd --sort=-pcpu,-rss --noheaders --width 120)"
processes_list="$(echo "$processes_list" | grep -v " ps$" | sed 's/ \+ / /g' | sed '/^$/d' | tr "\n" ";")"

file_handles=$(sed_rt $(to_num "$(cat /proc/sys/fs/file-nr | awk '{ print $1 }')"))
file_handles_limit=$(sed_rt $(to_num "$(cat /proc/sys/fs/file-nr | awk '{ print $3 }')"))

os_kernel=$(sed_rt "$(uname -r)")

if ls /etc/*release >/dev/null 2>&1; then
  os_name=$(sed_rt "$(cat /etc/*release | grep '^PRETTY_NAME=\|^NAME=\|^DISTRIB_ID=' | awk -F\= '{ print $2 }' | tr -d '"' | tac)")
fi

if [ -z "$os_name" ]; then
  if [ -e /etc/redhat-release ]; then
    os_name=$(sed_rt "$(cat /etc/redhat-release)")
  elif [ -e /etc/debian_version ]; then
    os_name=$(sed_rt "Debian $(cat /etc/debian_version)")
  fi

  if [ -z "$os_name" ]; then
    os_name=$(sed_rt "$(uname -s)")
  fi
fi

case $(uname -m) in
x86_64)
  os_arch=$(sed_rt "x64")
  ;;
i*86)
  os_arch=$(sed_rt "x86")
  ;;
*)
  os_arch=$(sed_rt "$(uname -m)")
  ;;
esac

cpu_name=$(sed_rt "$(cat /proc/cpuinfo | grep 'model name' | awk -F\: '{ print $2 }')")
cpu_cores=$(sed_rt "$(($(cat /proc/cpuinfo | grep 'model name' | awk -F\: '{ print $2 }' | sed -e :a -e '$!N;s/\n/\|/;ta' | tr -cd \| | wc -c) + 1))")

if [ -z "$cpu_name" ]; then
  cpu_name=$(sed_rt "$(cat /proc/cpuinfo | grep 'vendor_id' | awk -F\: '{ print $2 } END { if (!NR) print "N/A" }')")
  cpu_cores=$(sed_rt "$(($(cat /proc/cpuinfo | grep 'vendor_id' | awk -F\: '{ print $2 }' | sed -e :a -e '$!N;s/\n/\|/;ta' | tr -cd \| | wc -c) + 1))")
fi

cpu_freq=$(sed_rt "$(cat /proc/cpuinfo | grep 'cpu MHz' | awk -F\: '{ print $2 }')")

if [ -z "$cpu_freq" ]; then
  cpu_freq=$(sed_rt $(to_num "$(lscpu | grep 'CPU MHz' | awk -F\: '{ print $2 }' | sed -e 's/^ *//g' -e 's/ *$//g')"))
fi

ram_total=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^MemTotal: | awk '{ print $2 }')"))
ram_free=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^MemFree: | awk '{ print $2 }')"))
ram_cached=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^Cached: | awk '{ print $2 }')"))
ram_buffers=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^Buffers: | awk '{ print $2 }')"))
ram_usage=$((($ram_total - ($ram_free + $ram_cached + $ram_buffers)) * 1024))
ram_total=$(($ram_total * 1024))

swap_total=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^SwapTotal: | awk '{ print $2 }')"))
swap_free=$(sed_rt $(to_num "$(cat /proc/meminfo | grep ^SwapFree: | awk '{ print $2 }')"))
swap_usage=$((($swap_total - $swap_free) * 1024))
swap_total=$(($swap_total * 1024))

disk_total=$(sed_rt $(to_num "$(($(df -P -B 1 | grep '^/' | awk '{ print $2 }' | sed -e :a -e '$!N;s/\n/+/;ta')))"))
disk_usage=$(sed_rt $(to_num "$(($(df -P -B 1 | grep '^/' | awk '{ print $3 }' | sed -e :a -e '$!N;s/\n/+/;ta')))"))

disk_array=$(sed_rt "$(df -P -B 1 | grep '^/' | awk '{ print $1" "$2" "$3";" }' | sed -e :a -e '$!N;s/\n/ /;ta' | awk '{ print $0 } END { if (!NR) print "N/A" }')")

if [ -n "$(command -v ss)" ];
then
  connections=$(sed_rt $(to_num "$(ss -tun | tail -n +2 | wc -l)"))
else
  connections=$(sed_rt $(to_num "$(netstat -tun | tail -n +3 | wc -l)"))
fi

nic=$(sed_rt "$(ip route get 8.8.8.8 | grep dev | awk -F'dev' '{ print $2 }' | awk '{ print $1 }')")

if [ -z $nic ]; then
  nic=$(sed_rt "$(ip link show | grep 'eth[0-9]' | awk '{ print $2 }' | tr -d ':')")
fi

ipv4=$(sed_rt "$(ip addr show $nic | grep 'inet ' | awk '{ print $2 }' | awk -F\/ '{ print $1 }' | grep -v '^127' | awk '{ print $0 } END { if (!NR) print "N/A" }')")
ipv6=$(sed_rt "$(ip addr show $nic | grep 'inet6 ' | awk '{ print $2 }' | awk -F\/ '{ print $1 }' | grep -v '^::' | grep -v '^0000:' | grep -v '^fe80:' | awk '{ print $0 } END { if (!NR) print "N/A" }')")

if [ -d /sys/class/net/$nic/statistics ]; then
  rx=$(sed_rt $(to_num "$(cat /sys/class/net/$nic/statistics/rx_bytes)"))
  tx=$(sed_rt $(to_num "$(cat /sys/class/net/$nic/statistics/tx_bytes)"))
else
  rx=$(sed_rt $(to_num "$(ip -s link show $nic | grep '[0-9]*' | grep -v '[A-Za-z]' | awk '{ print $1 }' | sed -n '1 p')"))
  tx=$(sed_rt $(to_num "$(ip -s link show $nic | grep '[0-9]*' | grep -v '[A-Za-z]' | awk '{ print $1 }' | sed -n '2 p')"))
fi

load=$(sed_rt "$(cat /proc/loadavg | awk '{ print $1" "$2" "$3 }')")

time=$(date +%s)
stat=($(cat /proc/stat | head -n1 | sed 's/[^0-9 ]*//g' | sed 's/^ *//'))
cpu=$((${stat[0]} + ${stat[1]} + ${stat[2]} + ${stat[3]}))
io=$((${stat[3]} + ${stat[4]}))
idle=${stat[3]}

if [ -e /etc/syAgent/pe-data.log ];
then
  data=($(cat /etc/syAgent/pe-data.log))
  interval=$(($time - ${data[0]}))
  cpu_gap=$(($cpu - ${data[1]}))
  io_gap=$(($io - ${data[2]}))
  idle_gap=$(($idle - ${data[3]}))

  if [[ $cpu_gap > "0" ]];
  then
    load_cpu=$(((1000 * ($cpu_gap - $idle_gap) / $cpu_gap + 5) / 10))
  fi

  if [[ $io_gap > "0" ]];
  then
    load_io=$(((1000 * ($io_gap - $idle_gap) / $io_gap + 5) / 10))
  fi

  if [[ $rx > ${data[4]} ]];
  then
    rx_gap=$(($rx - ${data[4]}))
  fi

  if [[ $tx > ${data[5]} ]];
  then
    tx_gap=$(($tx - ${data[5]}))
  fi
fi

rx_gap=$(sed_rt $(to_num "$rx_gap"))
tx_gap=$(sed_rt $(to_num "$tx_gap"))
load_cpu=$(sed_rt $(to_num "$load_cpu"))
load_io=$(sed_rt $(to_num "$load_io"))
port_check=$(timeout 2 bash -c "</dev/tcp/google.com/808"; echo $?)
expire_date=$(timeout 3 openssl s_client -connect google.com:443 -servername google.com 2> /dev/null | openssl x509 -noout -dates | awk -F '=' '{print $2}' | sed -n '2p' |  awk {'print $1 " " $2 " "$4'})
publicIP=$(wget -qO - icanhazip.com)

dockerfullid_mariadb=$(docker container ls --all --quiet --no-trunc --filter "name=mariadb")
dockercreated_mariadb=$(docker inspect $dockerfullid_mariadb | grep -i created | tr -d " \t\n\r")
dockerstate_mariadb=$(docker ps --filter name=mariadb --format '{{json .}}' | jq | grep -i state)
mariadb_stats=$(docker stats $dockerfullid_mariadb --no-stream)
dockerstatus_mariadb=$(docker ps --filter name=mariadb | awk '{print $7,$8,$9,$11}' | tail -1)


echo -e "\n Docker stats for mariadb_____________________________________"
echo "mariadb docker full ID: "$dockerfullid_mariadb 
echo "mariadb docker created time: "$dockercreated_mariadb
echo "mariadb docker state: "$dockerstate_mariadb
echo "mariadb docker stats: "$mariadb_stats
echo "mariadb docker status: "$dockerstatus_mariadb


echo -e "\n"

multipart_data="data=$(to_base64 "publicIP:$publicIP") $(to_base64 "version:$version") $(to_base64 "uptime:$uptime") $(to_base64 "os_name:$os_name") $(to_base64 "cpu_freq:$cpu_freq")
$(to_base64 "ram_usage:$ram_usage") $(to_base64 "ram_total:$ram_total") $(to_base64 "disk_usage:$disk_usage") $(to_base64 "rx:$rx") $(to_base64 "tx:$tx")
$(to_base64 "load:$load") $(to_base64 "load_cpu:$load_cpu") $(to_base64 "load_io:$load_io") $(to_base64 "mariadb docker full ID:$dockerfullid_mariadb")
$(to_base64 "mariadb docker created time:$dockercreated_mariadb") $(to_base64 "mariadb docker stats: $mariadb_stats") $(to_base64 "mariadb docker status:$dockerstatus_mariadb")"

#$(to_base64 "") $(to_base64 "") $(to_base64 "")"
echo $multipart_data

#curl -k -s -X POST -H "Content-Type: multipart/form-data" -F "$multipart_data"  http://cluster.aamarpay.com/cluster-server/api/post-stats/$publicIP #Need to add static url here.
wget -T 25 --post-data "$multipart_data" --no-check-certificate "http://cluster.aamarpay.com/cluster-server/api/post-stats/$publicIP" > /dev/null

#docker log
curl -F log_file=@/var/lib/docker/containers/$log_path/$log_path-json.log http://cluster.aamarpay.com/cluster-server/api/post-logs/$publicIP
exit 0