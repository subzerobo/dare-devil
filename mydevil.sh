#!/bin/bash
# run this script on swarm enabled docker
# pull, build and deploy daredevil
# Amin Shayan [ amin@shayan.net ]
set -e 
shopt -s huponexit

# vars
PATH=/usr/local/bin:$PATH
PATH_PROG="$(readlink -m $(dirname $0))"
PATH_FIREHOL="${PATH_PROG}/firehol"
PATH_IP2LOCATION="${PATH_PROG}/ip2location"

BIN_PROG="$(basename $0)"

# traps
trap "exit" SIGHUP SIGINT SIGTERM

# local funcs
locker() {
  # prevent more than one instance to run
  if [[ 1 -ne $(fuser "$0" 2>/dev/null | wc -w) ]]; then
    echo "this script is already running. exiting."
    exit 1
  fi
}

# funcs
_deploy_daredevil_latest () {
  echo "deploying daredevil:latest ..."
  docker rm $(docker ps -a -q) || true
  docker stack deploy -c ${PATH_PROG}/docker-compose.yml daredevil --prune
  docker service update --force --image daredevil:latest daredevil_daredevil
  echo "done"
}

_build_daredevil_latest () {
  echo "building daredevil:latest ..."
  docker build --no-cache --build-arg HTTP_PROXY="http://bridge.saba-e.com:9999" --build-arg HTTPS_PROXY="http://yourhttpproxysever.com:2222" -t daredevil:$(git --git-dir="${PATH_PROG}/.git" log --pretty=format:'%h' -n 1) "${PATH_PROG}"
  docker tag daredevil:$(git --git-dir="${PATH_PROG}/.git" log --pretty=format:'%h' -n 1) daredevil:latest
  echo "done"
}

_update_firehol () {
  echo "updating firehol ..."
  rm -fr ${PATH_FIREHOL}
  git clone --depth 1 https://github.com/firehol/blocklist-ipsets.git ${PATH_FIREHOL}
  find ${PATH_FIREHOL} ! -path ${PATH_FIREHOL} ! -name "firehol_*.netset" -exec rm -fr {} \;  || true
  echo "done"
}

_update_ip2location () {
  echo "updating ip2location ..."
  rm -fr ${PATH_IP2LOCATION}
  mkdir ${PATH_IP2LOCATION}
  wget -O ${PATH_IP2LOCATION}/DB4-IP-COUNTRY-REGION-CITY-ISP.BIN.ZIP 'http://www.ip2location.com/download?productcode=DB4BIN&login=youremail@example.com&password=yourIP2CountryAccountPassword'
  unzip ${PATH_IP2LOCATION}/DB4-IP-COUNTRY-REGION-CITY-ISP.BIN.ZIP -d ${PATH_IP2LOCATION}
  find ${PATH_IP2LOCATION} ! -path ${PATH_IP2LOCATION} ! -name "*.BIN" -exec rm -fr {} \; || true
  echo "done"
}

_generate_crontab () {
  echo "# Updating Firehol"
  echo "0 14 * * * ${PATH_PROG}/${BIN_PROG} _update_firehol"
  echo "# Updating IP2Location"
  echo "0 15 * * 5 ${PATH_PROG}/${BIN_PROG} _update_ip2location"
  echo "# Building DareDevil"
  echo "0 18 * * * ${PATH_PROG}/${BIN_PROG} _build_daredevil_latest"
  echo "# Updating Swarm"
  echo "0 3 * * * ${PATH_PROG}/${BIN_PROG} _deploy_daredevil_latest"
}

main () {
  local c=0
  local func clist csel answer
  local funcs=$(typeset -f |egrep -o "^_[^[:space:]]+" )

  if [[ -n $@ ]]; then
    $@
    exit
  fi
  
  for func in $funcs; do
    c=$((${c}+1))
    echo "[${c}] ${func}"
  done
  echo

  if ((${c})); then
    if [[ ${c} -gt 1 ]]; then
      clist=${c}
    else
      clist=1
    fi
    echo -n "choose func to exec: " 
    while read -r answer; do
      if [[ ${answer} -ge 1 && ${answer} -le ${clist} ]]; then
        csel=${answer}
        break
      else
        echo "choose right func num to exec"
        echo -n "choose func to exec: " 
        continue
      fi
    done

    echo
    eval "$(echo ${funcs} |awk -v csel=${csel} '{print $csel}')"
  else
    echo "no func to exec."
  fi
}

# fire
main $@
