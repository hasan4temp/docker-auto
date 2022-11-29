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

#multipart_data="data=$(to_base64 "version:$version") $(to_base64 "uptime:$uptime") $(to_base64 "$sessions") $(to_base64 "$processes") 
#$(to_base64 "$processes_list") $(to_base64 "$file_handles") $(to_base64 "$file_handles_limit") $(to_base64 "$os_kernel") $(to_base64 "$os_name") 
#$(to_base64 "$os_arch") $(to_base64 "$cpu_name") $(to_base64 "$cpu_cores") $(to_base64 "$cpu_freq") $(to_base64 "$ram_total") 
#$(to_base64 "$ram_usage") $(to_base64 "$swap_total") $(to_base64 "$swap_usage") $(to_base64 "$disk_array") 
#$(to_base64 "$disk_total") $(to_base64 "$disk_usage") $(to_base64 "$connections") $(to_base64 "$nic") $(to_base64 "$ipv4") $(to_base64 "$ipv6") 
#$(to_base64 "$rx") $(to_base64 "$tx") $(to_base64 "$rx_gap") $(to_base64 "$tx_gap") $(to_base64 "$load") $(to_base64 "$load_cpu") 
#$(to_base64 "$load_io") $(to_base64 "$port_check") $(to_base64 "$expire_date")"

#docker log
#docker_log=$(curl -F file=@/var/lib/docker/containers/$log_path/$log_path-json.log https://store1.gofile.io/uploadFile)
dockerfullid_mariadb=$(docker container ls --all --quiet --no-trunc --filter "name=mariadb")
dockercreated_mariadb=$(docker inspect $dockerfullid_mariadb | grep -i created | tr -d " \t\n\r")
#dockerstatus_mariadb=$(docker ps --filter name=mariadb | awk '{print $7,$8,$9}' | tail -1)
dockerstatus_mariadb=$(docker ps --filter name=mariadb --format '{{json .}}' | jq | grep -i status)
dockerstate_mariadb=$(docker ps --filter name=mariadb --format '{{json .}}' | jq | grep -i state)

echo -e "\n Docker stats for mariadb_____________________________________"
echo "mariadb docker full ID: "$dockerfullid_mariadb 
echo "mariadb docker created time: "$dockercreated_mariadb
echo "mariadb docker status: "$dockerstatus_mariadb
echo "mariadb docker state: "$dockerstate_mariadb

echo -e "\n"

dockerfullid_phpmyadmin=$(docker container ls --all --quiet --no-trunc --filter "name=phpmyadmin")
dockercreated_phpmyadmin=$(docker inspect $dockerfullid_phpmyadmin | grep -i created | tr -d " \t\n\r")
#dockerstatus_phpmyadmin=$(docker ps --filter name=phpmyadmin | awk '{print $7,$8,$9}' | tail -1)
dockerstatus_phpmyadmin=$(docker ps --filter name=mariadb --format '{{json .}}' | jq | grep -i status)
dockerstate_phpmyadmin=$(docker ps --filter name=phpmyadmin --format '{{json .}}' | jq | grep -i state)

echo -e "\n Docker stats for phpmyadmin_____________________________________"
echo -e "phpmyadmin docker full ID: "$dockerfullid_phpmyadmin
echo -e "phpmyadmin docker created time: "$dockercreated_phpmyadmin
echo -e "phpmyadmin docker status: "$dockerstatus_phpmyadmin
echo -e "phpmyadmin docker state: "$dockerstate_phpmyadmin

multipart_data="data=$(to_base64 "publicIP:$publicIP") $(to_base64 "version:$version") $(to_base64 "uptime:$uptime") $(to_base64 "os_name:$os_name") $(to_base64 "cpu_freq:$cpu_freq")
$(to_base64 "ram_usage:$ram_usage") $(to_base64 "ram_total:$ram_total") $(to_base64 "disk_usage:$disk_usage") $(to_base64 "rx:$rx") $(to_base64 "tx:$tx")
$(to_base64 "load:$load") $(to_base64 "load_cpu:$load_cpu") $(to_base64 "load_io:$load_io") $(to_base64 "phpmyadmin docker full ID:$dockerfullid_phpmyadmin")
$(to_base64 "phpmyadmin docker created time:$dockercreated_phpmyadmin") $(to_base64 "phpmyadmin docker status:$dockerstatus_phpmyadmin") $(to_base64 "phpmyadmin docker state:$dockerstate_phpmyadmin") $(to_base64 "mariadb docker full ID:$dockerfullid_mariadb")
$(to_base64 "mariadb docker created time:$dockercreated_mariadb") $(to_base64 "mariadb docker status:$dockerstatus_mariadb") $(to_base64 "mariadb docker state:$dockerstate_mariadb")" 
#$(to_base64 "") $(to_base64 "") $(to_base64 "") $(to_base64 "")"
echo $multipart_data

curl -s -X POST -H "Content-Type: multipart/form-data" -F "$multipart_data" $1

<<com
echo "expire= $expire_date"
echo "port_check = $port_check" #if not eq to 0, port no open
echo "version = $version"
echo "uptime = $uptime"
echo "sessions = $sessions"
echo "processes = $processes"
echo "processes_list = $processes_list"
echo "file_handles = $file_handles"
echo "file_handles_limit = $file_handles_limit"
echo "os_kernel = $os_kernel"
echo "os_name = $os_name"
echo "os_arch = $os_arch"
echo "cpu_name = $cpu_name"
echo "cpu_cores = $cpu_cores"
echo "cpu_freq = $cpu_freq"
echo "ram_buffers = $ram_buffers"
echo "ram_usage = $ram_usage"
echo "ram_total = $ram_total"
echo "swap_total = $swap_total"
echo "swap_free = $swap_free"
echo "swap_usage = $swap_usage"
echo "swap_total = $swap_total"
echo "disk_total = $disk_total"
echo "disk_usage = $disk_usage"
echo "disk_array = $disk_array"
echo "connections = $connections"
echo "nic = $nic"
echo "ipv4 = $ipv4"
echo "ipv6 = $ipv6"
echo "rx = $rx"
echo "tx = $tx"
echo "load = $load"
echo "stat = $stat"
echo "cpu = $cpu"
echo "io = $io"
echo "idle = $idle"
echo "interval = $interval"
echo "cpu_gap $cpu_gap"
echo "io_gap $io_gap"
echo "idle_gap $idle_gap"
echo "load_cpu $load_cpu"
echo "load_io $load_io"
echo "rx_gap $rx_gap"
echo "tx_gap $tx_gap"
echo "rx_gap $rx_gap"
echo "tx_gap $tx_gap"
echo "load_cpu $load_cpu"
echo "load_io $load_io"
echo "multipart_data $multipart_data"

if [ -n "$(command -v timeout)" ]
then
  timeout -s SIGKILL 30 wget -q -o /dev/null -O /etc/syAgent/sh-agent.log -T 25 --post-data "$multipart_data" --no-check-certificate "https://agent.syagent.com/agent"
else
  wget -q -o /dev/null -O /etc/syAgent/sh-agent.log -T 25 --post-data "$multipart_data" --no-check-certificate "https://agent.syagent.com/agent"
  wget_process_id=$!
  wget_counter=0
  wget_timeout=30

  while kill -0 "$wget_process_id" && ((wget_counter < wget_timeout)); do
    sleep 1
    ((wget_counter++))
  done

  kill -0 "$wget_process_id" && kill -s SIGKILL "$wget_process_id"
fi
com
exit 0
