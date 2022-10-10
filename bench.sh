#!/usr/bin/env bash

log="./bench.log"
true > $log

{



echo ""
echo " A Multiple Bench Script By Wanji.info"
echo " Usage: bash <(wget -qO- bench.wanji.info)"
# echo "------------------------------------------------------------------------------"
echo ""

# Description: A Bench Script by Teddysun
#
# Copyright (C) 2015 - 2022 Teddysun <i@teddysun.com>
# Thanks: LookBack <admin@dwhd.org>
# URL: https://teddysun.com/444.html
# https://github.com/teddysun/across/blob/master/bench.sh
#
trap _exit INT QUIT TERM

_red() {
    printf '\033[0;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[0;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[0;31;33m%b\033[0m' "$1"
}

_blue() {
    printf '\033[0;31;36m%b\033[0m' "$1"
}

_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

_exit() {
    _red "\nThe script has been terminated.\n"
    # clean up
    rm -fr speedtest.tgz speedtest-cli benchtest_*
    exit 1
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print $0}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

next() {
    printf "%-70s\n" "-" | sed 's/\s/-/g'
}

speed_test() {
    local nodeName="$2"
    [ -z "$1" ] && ./speedtest-cli/speedtest --progress=no --accept-license --accept-gdpr > ./speedtest-cli/speedtest.log 2>&1 || \
    ./speedtest-cli/speedtest --progress=no --server-id=$1 --accept-license --accept-gdpr > ./speedtest-cli/speedtest.log 2>&1
    if [ $? -eq 0 ]; then
        local dl_speed=$(awk '/Download/{print $3" "$4}' ./speedtest-cli/speedtest.log)
        local up_speed=$(awk '/Upload/{print $3" "$4}' ./speedtest-cli/speedtest.log)
        local latency=$(awk '/Latency/{print $2" "$3}' ./speedtest-cli/speedtest.log)
        if [[ -n "${dl_speed}" && -n "${up_speed}" && -n "${latency}" ]]; then
            printf "\033[0;33m%-18s\033[0;32m%-18s\033[0;31m%-20s\033[0;36m%-12s\033[0m\n" " ${nodeName}" "${up_speed}" "${dl_speed}" "${latency}"
        fi
    fi
}

speed() {
    speed_test '' 'Speedtest.net'
    speed_test '21541' 'Los Angeles, US'
    speed_test '43860' 'Dallas, US'
    speed_test '40879' 'Montreal, CA'
    speed_test '24215' 'Paris, FR'
    speed_test '28922' 'Amsterdam, NL'
    speed_test '32155' 'Hongkong, CN'
    speed_test '6527'  'Seoul, KR'
    speed_test '7311'  'Singapore, SG'
    speed_test '21569' 'Tokyo, JP'
}

io_test() {
    (LANG=C dd if=/dev/zero of=benchtest_$$ bs=512k count=$1 conv=fdatasync && rm -f benchtest_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
}

calc_size() {
    local raw=$1
    local total_size=0
    local num=1
    local unit="KB"
    if ! [[ ${raw} =~ ^[0-9]+$ ]] ; then
        echo ""
        return
    fi
    if [ "${raw}" -ge 1073741824 ]; then
        num=1073741824
        unit="TB"
    elif [ "${raw}" -ge 1048576 ]; then
        num=1048576
        unit="GB"
    elif [ "${raw}" -ge 1024 ]; then
        num=1024
        unit="MB"
    elif [ "${raw}" -eq 0 ]; then
        echo "${total_size}"
        return
    fi
    total_size=$( awk 'BEGIN{printf "%.1f", '$raw' / '$num'}' )
    echo "${total_size} ${unit}"
}

check_virt(){
    _exists "dmesg" && virtualx="$(dmesg 2>/dev/null)"
    if _exists "dmidecode"; then
        sys_manu="$(dmidecode -s system-manufacturer 2>/dev/null)"
        sys_product="$(dmidecode -s system-product-name 2>/dev/null)"
        sys_ver="$(dmidecode -s system-version 2>/dev/null)"
    else
        sys_manu=""
        sys_product=""
        sys_ver=""
    fi
    if   grep -qa docker /proc/1/cgroup; then
        virt="Docker"
    elif grep -qa lxc /proc/1/cgroup; then
        virt="LXC"
    elif grep -qa container=lxc /proc/1/environ; then
        virt="LXC"
    elif [[ -f /proc/user_beancounters ]]; then
        virt="OpenVZ"
    elif [[ "${virtualx}" == *kvm-clock* ]]; then
        virt="KVM"
    elif [[ "${sys_product}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *QEMU* ]]; then
        virt="KVM"
    elif [[ "${virtualx}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${sys_product}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${virtualx}" == *"Parallels Software International"* ]]; then
        virt="Parallels"
    elif [[ "${virtualx}" == *VirtualBox* ]]; then
        virt="VirtualBox"
    elif [[ -e /proc/xen ]]; then
        if grep -q "control_d" "/proc/xen/capabilities" 2>/dev/null; then
            virt="Xen-Dom0"
        else
            virt="Xen-DomU"
        fi
    elif [ -f "/sys/hypervisor/type" ] && grep -q "xen" "/sys/hypervisor/type"; then
        virt="Xen"
    elif [[ "${sys_manu}" == *"Microsoft Corporation"* ]]; then
        if [[ "${sys_product}" == *"Virtual Machine"* ]]; then
            if [[ "${sys_ver}" == *"7.0"* || "${sys_ver}" == *"Hyper-V" ]]; then
                virt="Hyper-V"
            else
                virt="Microsoft Virtual Machine"
            fi
        fi
    else
        virt="Dedicated"
    fi
}

checkcurl() {
	if  [ ! -e '/usr/bin/curl' ]; then
	        echo "正在安装 Curl"
	            if [ "${release}" == "centos" ]; then
	                yum update > /dev/null 2>&1
	                yum -y install curl > /dev/null 2>&1
	            else
	                apt-get update > /dev/null 2>&1
	                apt-get -y install curl > /dev/null 2>&1
	            fi
	fi
}

checkwget() {
	if  [ ! -e '/usr/bin/wget' ]; then
	        echo "正在安装 Wget"
	            if [ "${release}" == "centos" ]; then
	                yum update > /dev/null 2>&1
	                yum -y install wget > /dev/null 2>&1
	            else
	                apt-get update > /dev/null 2>&1
	                apt-get -y install wget > /dev/null 2>&1
	            fi
	fi
}

ipv4_info() {
    local org="$(wget -q -T10 -O- ipinfo.io/org)"
    local city="$(wget -q -T10 -O- ipinfo.io/city)"
    local country="$(wget -q -T10 -O- ipinfo.io/country)"
    local region="$(wget -q -T10 -O- ipinfo.io/region)"
    if [[ -n "$org" ]]; then
        echo " Organization       : $(_blue "$org")"
    fi
    if [[ -n "$city" && -n "country" ]]; then
        echo " Location           : $(_blue "$city / $country")"
    fi
    if [[ -n "$region" ]]; then
        echo " Region             : $(_yellow "$region")"
    fi
    if [[ -z "$org" ]]; then
        echo " Region             : $(_red "No ISP detected")"
    fi
}

install_speedtest() {
    if [ ! -e "./speedtest-cli/speedtest" ]; then
        sys_bit=""
        local sysarch="$(uname -m)"
        if [ "${sysarch}" = "unknown" ] || [ "${sysarch}" = "" ]; then
            local sysarch="$(arch)"
        fi
        if [ "${sysarch}" = "x86_64" ]; then
            sys_bit="x86_64"
        fi
        if [ "${sysarch}" = "i386" ] || [ "${sysarch}" = "i686" ]; then
            sys_bit="i386"
        fi
        if [ "${sysarch}" = "armv8" ] || [ "${sysarch}" = "armv8l" ] || [ "${sysarch}" = "aarch64" ] || [ "${sysarch}" = "arm64" ]; then
            sys_bit="aarch64"
        fi
        if [ "${sysarch}" = "armv7" ] || [ "${sysarch}" = "armv7l" ]; then
            sys_bit="armhf"
        fi
        if [ "${sysarch}" = "armv6" ]; then
            sys_bit="armel"
        fi
        [ -z "${sys_bit}" ] && _red "Error: Unsupported system architecture (${sysarch}).\n" && exit 1
        url1="https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-linux-${sys_bit}.tgz"
        url2="https://dl.lamp.sh/files/ookla-speedtest-1.1.1-linux-${sys_bit}.tgz"
        wget --no-check-certificate -q -T10 -O speedtest.tgz ${url1}
        if [ $? -ne 0 ]; then
            wget --no-check-certificate -q -T10 -O speedtest.tgz ${url2}
            [ $? -ne 0 ] && _red "Error: Failed to download speedtest-cli.\n" && exit 1
        fi
        mkdir -p speedtest-cli && tar zxf speedtest.tgz -C ./speedtest-cli && chmod +x ./speedtest-cli/speedtest
        rm -f speedtest.tgz
    fi
    printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency"
}

print_intro() {
    echo "-------------------- A Bench.sh Script By Teddysun -------------------"
    echo " Version            : $(_green v2022-06-01)"
    echo " Usage              : $(_red "wget -qO- bench.sh | bash")"
}

# Get System information
get_system_info() {
    cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cores=$( awk -F: '/processor/ {core++} END {print core}' /proc/cpuinfo )
    freq=$( awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo )
    ccache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cpu_aes=$( grep -i 'aes' /proc/cpuinfo )
    cpu_virt=$( grep -Ei 'vmx|svm' /proc/cpuinfo )
    tram=$( LANG=C; free | awk '/Mem/ {print $2}' )
    tram=$( calc_size $tram )
    uram=$( LANG=C; free | awk '/Mem/ {print $3}' )
    uram=$( calc_size $uram )
    swap=$( LANG=C; free | awk '/Swap/ {print $2}' )
    swap=$( calc_size $swap )
    uswap=$( LANG=C; free | awk '/Swap/ {print $3}' )
    uswap=$( calc_size $uswap )
    up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime )
    if _exists "w"; then
        load=$( LANG=C; w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    elif _exists "uptime"; then
        load=$( LANG=C; uptime | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    fi
    opsy=$( get_opsy )
    arch=$( uname -m )
    if _exists "getconf"; then
        lbit=$( getconf LONG_BIT )
    else
        echo ${arch} | grep -q "64" && lbit="64" || lbit="32"
    fi
    kern=$( uname -r )
    disk_total_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $2 }' )
    disk_total_size=$( calc_size $disk_total_size )
    disk_used_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $3 }' )
    disk_used_size=$( calc_size $disk_used_size )
    tcpctrl=$( sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}' )
}
# Print System information
print_system_info() {
    if [ -n "$cname" ]; then
        echo " CPU Model          : $(_blue "$cname")"
    else
        echo " CPU Model          : $(_blue "CPU model not detected")"
    fi
    if [ -n "$freq" ]; then
        echo " CPU Cores          : $(_blue "$cores @ $freq MHz")"
    else
        echo " CPU Cores          : $(_blue "$cores")"
    fi
    if [ -n "$ccache" ]; then
        echo " CPU Cache          : $(_blue "$ccache")"
    fi
    if [ -n "$cpu_aes" ]; then
        echo " AES-NI             : $(_green "Enabled")"
    else
        echo " AES-NI             : $(_red "Disabled")"
    fi
    if [ -n "$cpu_virt" ]; then
        echo " VM-x/AMD-V         : $(_green "Enabled")"
    else
        echo " VM-x/AMD-V         : $(_red "Disabled")"
    fi
    echo " Total Disk         : $(_yellow "$disk_total_size") $(_blue "($disk_used_size Used)")"
    echo " Total Mem          : $(_yellow "$tram") $(_blue "($uram Used)")"
    if [ "$swap" != "0" ]; then
        echo " Total Swap         : $(_blue "$swap ($uswap Used)")"
    fi
    echo " System uptime      : $(_blue "$up")"
    echo " Load average       : $(_blue "$load")"
    echo " OS                 : $(_blue "$opsy")"
    echo " Arch               : $(_blue "$arch ($lbit Bit)")"
    echo " Kernel             : $(_blue "$kern")"
    echo " TCP CC             : $(_yellow "$tcpctrl")"
    echo " Virtualization     : $(_blue "$virt")"
}

print_io_test() {
    freespace=$( df -m . | awk 'NR==2 {print $4}' )
    if [ -z "${freespace}" ]; then
        freespace=$( df -m . | awk 'NR==3 {print $3}' )
    fi
    if [ ${freespace} -gt 1024 ]; then
        writemb=2048
        io1=$( io_test ${writemb} )
        echo " I/O Speed(1st run) : $(_yellow "$io1")"
        io2=$( io_test ${writemb} )
        echo " I/O Speed(2nd run) : $(_yellow "$io2")"
        io3=$( io_test ${writemb} )
        echo " I/O Speed(3rd run) : $(_yellow "$io3")"
        ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
        [ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
        ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
        [ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
        ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
        [ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
        ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
        ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
        echo " I/O Speed(average) : $(_yellow "$ioavg MB/s")"
    else
        echo " $(_red "Not enough space for I/O Speed test!")"
    fi
}

print_end_time() {
    end_time=$(date +%s)
    time=$(( ${end_time} - ${start_time} ))
    if [ ${time} -gt 60 ]; then
        min=$(expr $time / 60)
        sec=$(expr $time % 60)
        echo " Finished in        : ${min} min ${sec} sec"
    else
        echo " Finished in        : ${time} sec"
    fi
    date_time=$(date '+%Y-%m-%d %H:%M:%S %Z')
    echo " Timestamp          : $date_time"
}

checkcurl;
checkwget;
! _exists "free" && _red "Error: free command not found.\n" && exit 1
start_time=$(date +%s)
get_system_info
check_virt
print_intro
next
print_system_info
ipv4_info
next

install_speedtest && speed && rm -fr speedtest-cli
next
print_end_time
next


#!/bin/bash

# Yet Another Bench Script by Mason Rowe
# Initial Oct 2019; Last update Aug 2022
#
# Disclaimer: This project is a work in progress. Any errors or suggestions should be
#             relayed to me via the GitHub project page linked below.
#
# Purpose:    The purpose of this script is to quickly gauge the performance of a Linux-
#             based server by benchmarking network performance via iperf3, CPU and
#             overall system performance via Geekbench 4/5, and random disk
#             performance via fio. The script is designed to not require any dependencies
#             - either compiled or installed - nor admin privileges to run.
#
YABS_VERSION="v2022-08-20"

echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## #' 
echo -e '#              Yet-Another-Bench-Script              #'
echo -e '#                     '$YABS_VERSION'                    #'
echo -e '# https://github.com/masonr/yet-another-bench-script #'
echo -e '# ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## #'

echo -e
date
TIME_START=$(date '+%Y%m%d-%H%M%S')

# override locale to eliminate parsing errors (i.e. using commas as delimiters rather than periods)
if locale -a | grep ^C$ > /dev/null ; then
	# locale "C" installed
	export LC_ALL=C
else
	# locale "C" not installed, display warning
	echo -e "\nWarning: locale 'C' not detected. Test outputs may not be parsed correctly."
fi

# determine architecture of host
ARCH=$(uname -m)
if [[ $ARCH = *x86_64* ]]; then
	# host is running a 64-bit kernel
	ARCH="x64"
elif [[ $ARCH = *i?86* ]]; then
	# host is running a 32-bit kernel
	ARCH="x86"
elif [[ $ARCH = *aarch* || $ARCH = *arm* ]]; then
	KERNEL_BIT=`getconf LONG_BIT`
	if [[ $KERNEL_BIT = *64* ]]; then
		# host is running an ARM 64-bit kernel
		ARCH="aarch64"
	else
		# host is running an ARM 32-bit kernel
		ARCH="arm"
	fi
	echo -e "\nARM compatibility is considered *experimental*"
else
	# host is running a non-supported kernel
	echo -e "Architecture not supported by YABS."
	exit 1
fi

# flags to skip certain performance tests
unset PREFER_BIN SKIP_FIO SKIP_IPERF SKIP_GEEKBENCH PRINT_HELP REDUCE_NET GEEKBENCH_4 GEEKBENCH_5 DD_FALLBACK IPERF_DL_FAIL JSON JSON_SEND JSON_RESULT JSON_FILE
GEEKBENCH_5="True" # gb5 test enabled by default

# get any arguments that were passed to the script and set the associated skip flags (if applicable)
while getopts 'bfdighr49jw:s:' flag; do
	case "${flag}" in
		b) PREFER_BIN="True" ;;
		f) SKIP_FIO="True" ;;
		d) SKIP_FIO="True" ;;
		i) SKIP_IPERF="True" ;;
		g) SKIP_GEEKBENCH="True" ;;
		h) PRINT_HELP="True" ;;
		r) REDUCE_NET="True" ;;
		4) GEEKBENCH_4="True" && unset GEEKBENCH_5 ;;
		9) GEEKBENCH_4="True" && GEEKBENCH_5="True" ;;
		j) JSON+="j" ;; 
		w) JSON+="w" && JSON_FILE=${OPTARG} ;;
		s) JSON+="s" && JSON_SEND=${OPTARG} ;; 
		*) exit 1 ;;
	esac
done

# check for local fio/iperf installs
command -v fio >/dev/null 2>&1 && LOCAL_FIO=true || unset LOCAL_FIO
command -v iperf3 >/dev/null 2>&1 && LOCAL_IPERF=true || unset LOCAL_IPERF

# check for curl/wget
command -v curl >/dev/null 2>&1 && LOCAL_CURL=true || unset LOCAL_CURL

# test if the host has IPv4/IPv6 connectivity
[[ ! -z $LOCAL_CURL ]] && IP_CHECK_CMD="curl -s -m 4" || IP_CHECK_CMD="wget -qO- -T 4"
IPV4_CHECK=$((ping -4 -c 1 -W 4 ipv4.google.com >/dev/null 2>&1 && echo true) || $IP_CHECK_CMD -4 icanhazip.com 2> /dev/null)
IPV6_CHECK=$((ping -6 -c 1 -W 4 ipv6.google.com >/dev/null 2>&1 && echo true) || $IP_CHECK_CMD -6 icanhazip.com 2> /dev/null)
if [[ -z "$IPV4_CHECK" && -z "$IPV6_CHECK" ]]; then
	echo -e
	echo -e "Warning: Both IPv4 AND IPv6 connectivity were not detected. Check for DNS issues..."
fi

# print help and exit script, if help flag was passed
if [ ! -z "$PRINT_HELP" ]; then
	echo -e
	echo -e "Usage: ./yabs.sh [-flags]"
	echo -e "       curl -sL yabs.sh | bash"
	echo -e "       curl -sL yabs.sh | bash -s -- -flags"
	echo -e "       wget -qO- yabs.sh | bash"
	echo -e "       wget -qO- yabs.sh | bash -s -- -flags"
	echo -e
	echo -e "Flags:"
	echo -e "       -b : prefer pre-compiled binaries from repo over local packages"
	echo -e "       -f/d : skips the fio disk benchmark test"
	echo -e "       -i : skips the iperf network test"
	echo -e "       -g : skips the geekbench performance test"
	echo -e "       -h : prints this lovely message, shows any flags you passed,"
	echo -e "            shows if fio/iperf3 local packages have been detected,"
	echo -e "            then exits"
	echo -e "       -r : reduce number of iperf3 network locations (to only three)"
	echo -e "            to lessen bandwidth usage"
	echo -e "       -4 : use geekbench 4 instead of geekbench 5"
	echo -e "       -9 : use both geekbench 4 AND geekbench 5"
	echo -e "       -j : print jsonified YABS results at conclusion of test"
	echo -e "       -w <filename> : write jsonified YABS results to disk using file name provided"
	echo -e "       -s <url> : send jsonified YABS results to URL"
	echo -e
	echo -e "Detected Arch: $ARCH"
	echo -e
	echo -e "Detected Flags:"
	[[ ! -z $PREFER_BIN ]] && echo -e "       -b, force using precompiled binaries from repo"
	[[ ! -z $SKIP_FIO ]] && echo -e "       -f/d, skipping fio disk benchmark test"
	[[ ! -z $SKIP_IPERF ]] && echo -e "       -i, skipping iperf network test"
	[[ ! -z $SKIP_GEEKBENCH ]] && echo -e "       -g, skipping geekbench test"
	[[ ! -z $REDUCE_NET ]] && echo -e "       -r, using reduced (3) iperf3 locations"
	[[ ! -z $GEEKBENCH_4 ]] && echo -e "       running geekbench 4"
	[[ ! -z $GEEKBENCH_5 ]] && echo -e "       running geekbench 5"
	echo -e
	echo -e "Local Binary Check:"
	[[ -z $LOCAL_FIO ]] && echo -e "       fio not detected, will download precompiled binary" ||
		[[ -z $PREFER_BIN ]] && echo -e "       fio detected, using local package" ||
		echo -e "       fio detected, but using precompiled binary instead"
	[[ -z $LOCAL_IPERF ]] && echo -e "       iperf3 not detected, will download precompiled binary" ||
		[[ -z $PREFER_BIN ]] && echo -e "       iperf3 detected, using local package" ||
		echo -e "       iperf3 detected, but using precompiled binary instead"
	echo -e
	echo -e "Detected Connectivity:"
	[[ ! -z $IPV4_CHECK ]] && echo -e "       IPv4 connected" ||
		echo -e "       IPv4 not connected"
	[[ ! -z $IPV6_CHECK ]] && echo -e "       IPv6 connected" ||
		echo -e "       IPv6 not connected"
	echo -e
	echo -e "JSON Options:"
	[[ -z $JSON ]] && echo -e "       none"
	[[ $JSON = *j* ]] && echo -e "       printing json to screen after test"
	[[ $JSON = *w* ]] && echo -e "       writing json to file ($JSON_FILE) after test"
	[[ $JSON = *s* ]] && echo -e "       sharing json YABS results to $JSON_SEND" 
	echo -e
	echo -e "Exiting..."

	exit 0
fi

# format_size
# Purpose: Formats raw disk and memory sizes from kibibytes (KiB) to largest unit
# Parameters:
#          1. RAW - the raw memory size (RAM/Swap) in kibibytes
# Returns:
#          Formatted memory size in KiB, MiB, GiB, or TiB
function format_size {
	RAW=$1 # mem size in KiB
	RESULT=$RAW
	local DENOM=1
	local UNIT="KiB"

	# ensure the raw value is a number, otherwise return blank
	re='^[0-9]+$'
	if ! [[ $RAW =~ $re ]] ; then
		echo "" 
		return 0
	fi

	if [ "$RAW" -ge 1073741824 ]; then
		DENOM=1073741824
		UNIT="TiB"
	elif [ "$RAW" -ge 1048576 ]; then
		DENOM=1048576
		UNIT="GiB"
	elif [ "$RAW" -ge 1024 ]; then
		DENOM=1024
		UNIT="MiB"
	fi

	# divide the raw result to get the corresponding formatted result (based on determined unit)
	RESULT=$(awk -v a="$RESULT" -v b="$DENOM" 'BEGIN { print a / b }')
	# shorten the formatted result to two decimal places (i.e. x.x)
	RESULT=$(echo $RESULT | awk -F. '{ printf "%0.1f",$1"."substr($2,1,2) }')
	# concat formatted result value with units and return result
	RESULT="$RESULT $UNIT"
	echo $RESULT
}

# gather basic system information (inc. CPU, AES-NI/virt status, RAM + swap + disk size)
# echo -e 
# echo -e "Basic System Information:"
# echo -e "---------------------------------"
UPTIME=$(uptime | awk -F'( |,|:)+' '{d=h=m=0; if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')
# echo -e "Uptime     : $UPTIME"
if [[ $ARCH = *aarch64* || $ARCH = *arm* ]]; then
	CPU_PROC=$(lscpu | grep "Model name" | sed 's/Model name: *//g')
else
	CPU_PROC=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
fi
# echo -e "Processor  : $CPU_PROC"
if [[ $ARCH = *aarch64* || $ARCH = *arm* ]]; then
	CPU_CORES=$(lscpu | grep "^[[:blank:]]*CPU(s):" | sed 's/CPU(s): *//g')
	CPU_FREQ=$(lscpu | grep "CPU max MHz" | sed 's/CPU max MHz: *//g')
	[[ -z "$CPU_FREQ" ]] && CPU_FREQ="???"
	CPU_FREQ="${CPU_FREQ} MHz"
else
	CPU_CORES=$(awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo)
	CPU_FREQ=$(awk -F: ' /cpu MHz/ {freq=$2} END {print freq " MHz"}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
fi
# echo -e "CPU cores  : $CPU_CORES @ $CPU_FREQ"
CPU_AES=$(cat /proc/cpuinfo | grep aes)
[[ -z "$CPU_AES" ]] && CPU_AES="\xE2\x9D\x8C Disabled" || CPU_AES="\xE2\x9C\x94 Enabled"
# echo -e "AES-NI     : $CPU_AES"
CPU_VIRT=$(cat /proc/cpuinfo | grep 'vmx\|svm')
[[ -z "$CPU_VIRT" ]] && CPU_VIRT="\xE2\x9D\x8C Disabled" || CPU_VIRT="\xE2\x9C\x94 Enabled"
# echo -e "VM-x/AMD-V : $CPU_VIRT"
TOTAL_RAM_RAW=$(free | awk 'NR==2 {print $2}')
TOTAL_RAM=$(format_size $TOTAL_RAM_RAW)
# echo -e "RAM        : $TOTAL_RAM"
TOTAL_SWAP_RAW=$(free | grep Swap | awk '{ print $2 }')
TOTAL_SWAP=$(format_size $TOTAL_SWAP_RAW)
# echo -e "Swap       : $TOTAL_SWAP"
# total disk size is calculated by adding all partitions of the types listed below (after the -t flags)
TOTAL_DISK_RAW=$(df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $2 }')
TOTAL_DISK=$(format_size $TOTAL_DISK_RAW)
# echo -e "Disk       : $TOTAL_DISK"
DISTRO=$(grep 'PRETTY_NAME' /etc/os-release | cut -d '"' -f 2 )
# echo -e "Distro     : $DISTRO"
KERNEL=$(uname -r)
# echo -e "Kernel     : $KERNEL"

# if [ ! -z $JSON ]; then
# 	UPTIME_S=$(awk '{print $1}' /proc/uptime)
# 	IPV4=$([ ! -z $IPV4_CHECK ] && echo "true" || echo "false")
# 	IPV6=$([ ! -z $IPV6_CHECK ] && echo "true" || echo "false")
# 	AES=$([[ "$CPU_AES" = *Enabled* ]] && echo "true" || echo "false")
# 	VIRT=$([[ "$CPU_VIRT" = *Enabled* ]] && echo "true" || echo "false")
# 	JSON_RESULT='{"version":"'$YABS_VERSION'","time":"'$TIME_START'","os":{"arch":"'$ARCH'","distro":"'$DISTRO'","kernel":"'$KERNEL'",'
# 	JSON_RESULT+='"uptime":'$UPTIME_S'},"net":{"ipv4":'$IPV4',"ipv6":'$IPV6'},"cpu":{"model":"'$CPU_PROC'","cores":'$CPU_CORES','
# 	JSON_RESULT+='"freq":"'$CPU_FREQ'","aes":'$AES',"virt":'$VIRT'},"mem":{"ram":'$TOTAL_RAM_RAW',"swap":'$TOTAL_SWAP_RAW',"disk":'$TOTAL_DISK_RAW'}'
# fi

# create a directory in the same location that the script is being run to temporarily store YABS-related files
DATE=`date -Iseconds | sed -e "s/:/_/g"`
YABS_PATH=./$DATE
touch $DATE.test 2> /dev/null
# test if the user has write permissions in the current directory and exit if not
if [ ! -f "$DATE.test" ]; then
	echo -e
	echo -e "You do not have write permission in this directory. Switch to an owned directory and re-run the script.\nExiting..."
	exit 1
fi
rm $DATE.test
mkdir -p $YABS_PATH

# trap CTRL+C signals to exit script cleanly
trap catch_abort INT

# catch_abort
# Purpose: This method will catch CTRL+C signals in order to exit the script cleanly and remove
#          yabs-related files.
function catch_abort() {
	echo -e "\n** Aborting YABS. Cleaning up files...\n"
	rm -rf $YABS_PATH
	unset LC_ALL
	exit 0
}

# format_speed
# Purpose: This method is a convenience function to format the output of the fio disk tests which
#          always returns a result in KB/s. If result is >= 1 GB/s, use GB/s. If result is < 1 GB/s
#          and >= 1 MB/s, then use MB/s. Otherwise, use KB/s.
# Parameters:
#          1. RAW - the raw disk speed result (in KB/s)
# Returns:
#          Formatted disk speed in GB/s, MB/s, or KB/s
function format_speed {
	RAW=$1 # disk speed in KB/s
	RESULT=$RAW
	local DENOM=1
	local UNIT="KB/s"

	# ensure raw value is not null, if it is, return blank
	if [ -z "$RAW" ]; then
		echo ""
		return 0
	fi

	# check if disk speed >= 1 GB/s
	if [ "$RAW" -ge 1000000 ]; then
		DENOM=1000000
		UNIT="GB/s"
	# check if disk speed < 1 GB/s && >= 1 MB/s
	elif [ "$RAW" -ge 1000 ]; then
		DENOM=1000
		UNIT="MB/s"
	fi

	# divide the raw result to get the corresponding formatted result (based on determined unit)
	RESULT=$(awk -v a="$RESULT" -v b="$DENOM" 'BEGIN { print a / b }')
	# shorten the formatted result to two decimal places (i.e. x.xx)
	RESULT=$(echo $RESULT | awk -F. '{ printf "%0.2f",$1"."substr($2,1,2) }')
	# concat formatted result value with units and return result
	RESULT="$RESULT $UNIT"
	echo $RESULT
}

# format_iops
# Purpose: This method is a convenience function to format the output of the raw IOPS result
# Parameters:
#          1. RAW - the raw IOPS result
# Returns:
#          Formatted IOPS (i.e. 8, 123, 1.7k, 275.9k, etc.)
function format_iops {
	RAW=$1 # iops
	RESULT=$RAW

	# ensure raw value is not null, if it is, return blank
	if [ -z "$RAW" ]; then
		echo ""
		return 0
	fi

	# check if IOPS speed > 1k
	if [ "$RAW" -ge 1000 ]; then
		# divide the raw result by 1k
		RESULT=$(awk -v a="$RESULT" 'BEGIN { print a / 1000 }')
		# shorten the formatted result to one decimal place (i.e. x.x)
		RESULT=$(echo $RESULT | awk -F. '{ printf "%0.1f",$1"."substr($2,1,1) }')
		RESULT="$RESULT"k
	fi

	echo $RESULT
}

# disk_test
# Purpose: This method is designed to test the disk performance of the host using the partition that the
#          script is being run from using fio random read/write speed tests.
# Parameters:
#          - (none)
function disk_test {
	if [[ "$ARCH" = "aarch64" || "$ARCH" = "arm" ]]; then
		FIO_SIZE=512M
	else
		FIO_SIZE=2G
	fi

	# run a quick test to generate the fio test file to be used by the actual tests
	echo -en "Generating fio test file..."
	$FIO_CMD --name=setup --ioengine=libaio --rw=read --bs=64k --iodepth=64 --numjobs=2 --size=$FIO_SIZE --runtime=1 --gtod_reduce=1 --filename=$DISK_PATH/test.fio --direct=1 --minimal &> /dev/null
	echo -en "\r\033[0K"

	# get array of block sizes to evaluate
	BLOCK_SIZES=("$@")

	for BS in "${BLOCK_SIZES[@]}"; do
		# run rand read/write mixed fio test with block size = $BS
		echo -en "Running fio random mixed R+W disk test with $BS block size..."
		DISK_TEST=$(timeout 35 $FIO_CMD --name=rand_rw_$BS --ioengine=libaio --rw=randrw --rwmixread=50 --bs=$BS --iodepth=64 --numjobs=2 --size=$FIO_SIZE --runtime=30 --gtod_reduce=1 --direct=1 --filename=$DISK_PATH/test.fio --group_reporting --minimal 2> /dev/null | grep rand_rw_$BS)
		DISK_IOPS_R=$(echo $DISK_TEST | awk -F';' '{print $8}')
		DISK_IOPS_W=$(echo $DISK_TEST | awk -F';' '{print $49}')
		DISK_IOPS=$(awk -v a="$DISK_IOPS_R" -v b="$DISK_IOPS_W" 'BEGIN { print a + b }')
		DISK_TEST_R=$(echo $DISK_TEST | awk -F';' '{print $7}')
		DISK_TEST_W=$(echo $DISK_TEST | awk -F';' '{print $48}')
		DISK_TEST=$(awk -v a="$DISK_TEST_R" -v b="$DISK_TEST_W" 'BEGIN { print a + b }')
		DISK_RESULTS_RAW+=( "$DISK_TEST" "$DISK_TEST_R" "$DISK_TEST_W" "$DISK_IOPS" "$DISK_IOPS_R" "$DISK_IOPS_W" )

		DISK_IOPS=$(format_iops $DISK_IOPS)
		DISK_IOPS_R=$(format_iops $DISK_IOPS_R)
		DISK_IOPS_W=$(format_iops $DISK_IOPS_W)
		DISK_TEST=$(format_speed $DISK_TEST)
		DISK_TEST_R=$(format_speed $DISK_TEST_R)
		DISK_TEST_W=$(format_speed $DISK_TEST_W)

		DISK_RESULTS+=( "$DISK_TEST" "$DISK_TEST_R" "$DISK_TEST_W" "$DISK_IOPS" "$DISK_IOPS_R" "$DISK_IOPS_W" )
		echo -en "\r\033[0K"
	done
}

# dd_test
# Purpose: This method is invoked if the fio disk test failed. dd sequential speed tests are
#          not indiciative or real-world results, however, some form of disk speed measure 
#          is better than nothing.
# Parameters:
#          - (none)
function dd_test {
	I=0
	DISK_WRITE_TEST_RES=()
	DISK_READ_TEST_RES=()
	DISK_WRITE_TEST_AVG=0
	DISK_READ_TEST_AVG=0

	# run the disk speed tests (write and read) thrice over
	while [ $I -lt 3 ]
	do
		# write test using dd, "direct" flag is used to test direct I/O for data being stored to disk
		DISK_WRITE_TEST=$(dd if=/dev/zero of=$DISK_PATH/$DATE.test bs=64k count=16k oflag=direct |& grep copied | awk '{ print $(NF-1) " " $(NF)}')
		VAL=$(echo $DISK_WRITE_TEST | cut -d " " -f 1)
		[[ "$DISK_WRITE_TEST" == *"GB"* ]] && VAL=$(awk -v a="$VAL" 'BEGIN { print a * 1000 }')
		DISK_WRITE_TEST_RES+=( "$DISK_WRITE_TEST" )
		DISK_WRITE_TEST_AVG=$(awk -v a="$DISK_WRITE_TEST_AVG" -v b="$VAL" 'BEGIN { print a + b }')

		# read test using dd using the 1G file written during the write test
		DISK_READ_TEST=$(dd if=$DISK_PATH/$DATE.test of=/dev/null bs=8k |& grep copied | awk '{ print $(NF-1) " " $(NF)}')
		VAL=$(echo $DISK_READ_TEST | cut -d " " -f 1)
		[[ "$DISK_READ_TEST" == *"GB"* ]] && VAL=$(awk -v a="$VAL" 'BEGIN { print a * 1000 }')
		DISK_READ_TEST_RES+=( "$DISK_READ_TEST" )
		DISK_READ_TEST_AVG=$(awk -v a="$DISK_READ_TEST_AVG" -v b="$VAL" 'BEGIN { print a + b }')

		I=$(( $I + 1 ))
	done
	# calculate the write and read speed averages using the results from the three runs
	DISK_WRITE_TEST_AVG=$(awk -v a="$DISK_WRITE_TEST_AVG" 'BEGIN { print a / 3 }')
	DISK_READ_TEST_AVG=$(awk -v a="$DISK_READ_TEST_AVG" 'BEGIN { print a / 3 }')
}

# check if disk performance is being tested and the host has required space (2G)
AVAIL_SPACE=`df -k . | awk 'NR==2{print $4}'`
if [[ -z "$SKIP_FIO" && "$AVAIL_SPACE" -lt 2097152 && "$ARCH" != "aarch64" && "$ARCH" != "arm" ]]; then # 2GB = 2097152KB
	echo -e "\nLess than 2GB of space available. Skipping disk test..."
elif [[ -z "$SKIP_FIO" && "$AVAIL_SPACE" -lt 524288 && ("$ARCH" = "aarch64" || "$ARCH" = "arm") ]]; then # 512MB = 524288KB
	echo -e "\nLess than 512MB of space available. Skipping disk test..."
# if the skip disk flag was set, skip the disk performance test, otherwise test disk performance
elif [ -z "$SKIP_FIO" ]; then
	# Perform ZFS filesystem detection and determine if we have enough free space according to spa_asize_inflation
	ZFSCHECK="/sys/module/zfs/parameters/spa_asize_inflation"
	if [[ -f "$ZFSCHECK" ]];then
		mul_spa=$((($(cat /sys/module/zfs/parameters/spa_asize_inflation)*2)))
		warning=0
		poss=()

		for pathls in $(df -Th | awk '{print $7}' | tail -n +2)
		do
			if [[ "${PWD##$pathls}" != "${PWD}" ]]; then
				poss+=($pathls)
			fi
		done

		long=""
		m=-1
		for x in ${poss[@]}
		do
			if [ ${#x} -gt $m ];then
				m=${#x}
				long=$x
			fi
		done

		size_b=$(df -Th | grep -w $long | grep -i zfs | awk '{print $5}' | tail -c 2 | head -c 1)
		free_space=$(df -Th | grep -w $long | grep -i zfs | awk '{print $5}' | head -c -2)

		if [[ $size_b == 'T' ]]; then
			free_space=$(bc <<< "$free_space*1024")
			size_b='G'
		fi

		if [[ $(df -Th | grep -w $long) == *"zfs"* ]];then

			if [[ $size_b == 'G' ]]; then
				if [[ $(echo "$free_space < $mul_spa" | bc) -ne 0 ]];then
					warning=1
				fi
			else
				warning=1
			fi

		fi

		if [[ $warning -eq 1 ]];then
			echo -en "\nWarning! You are running YABS on a ZFS Filesystem and your disk space is too low for the fio test. Your test results will be inaccurate. You need at least $mul_spa GB free in order to complete this test accurately. For more information, please see https://github.com/masonr/yet-another-bench-script/issues/13\n"
		fi
	fi
	
	echo -en "\nPreparing system for disk tests..."

	# create temp directory to store disk write/read test files
	DISK_PATH=$YABS_PATH/disk
	mkdir -p $DISK_PATH

	if [[ -z "$PREFER_BIN" && ! -z "$LOCAL_FIO" ]]; then # local fio has been detected, use instead of pre-compiled binary
		FIO_CMD=fio
	else
		# download fio binary
		if [[ ! -z $LOCAL_CURL ]]; then
			curl -s --connect-timeout 5 --retry 5 --retry-delay 0 https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_$ARCH -o $DISK_PATH/fio
		else
			wget -q -T 5 -t 5 -w 0 https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/fio/fio_$ARCH -O $DISK_PATH/fio
		fi

		if [ ! -f "$DISK_PATH/fio" ]; then # ensure fio binary download successfully
			echo -en "\r\033[0K"
			echo -e "Fio binary download failed. Running dd test as fallback...."
			DD_FALLBACK=True
		else
			chmod +x $DISK_PATH/fio
			FIO_CMD=$DISK_PATH/fio
		fi
	fi

	if [ -z "$DD_FALLBACK" ]; then # if not falling back on dd tests, run fio test
		echo -en "\r\033[0K"

		# init global array to store disk performance values
		declare -a DISK_RESULTS DISK_RESULTS_RAW
		# disk block sizes to evaluate
		BLOCK_SIZES=( "4k" "64k" "512k" "1m" )

		# execute disk performance test
		disk_test "${BLOCK_SIZES[@]}"
	fi

	if [[ ! -z "$DD_FALLBACK" || ${#DISK_RESULTS[@]} -eq 0 ]]; then # fio download failed or test was killed or returned an error, run dd test instead
		if [ -z "$DD_FALLBACK" ]; then # print error notice if ended up here due to fio error
			echo -e "fio disk speed tests failed. Run manually to determine cause.\nRunning dd test as fallback..."
		fi

		dd_test

		# format the speed averages by converting to GB/s if > 1000 MB/s
		if [ $(echo $DISK_WRITE_TEST_AVG | cut -d "." -f 1) -ge 1000 ]; then
			DISK_WRITE_TEST_AVG=$(awk -v a="$DISK_WRITE_TEST_AVG" 'BEGIN { print a / 1000 }')
			DISK_WRITE_TEST_UNIT="GB/s"
		else
			DISK_WRITE_TEST_UNIT="MB/s"
		fi
		if [ $(echo $DISK_READ_TEST_AVG | cut -d "." -f 1) -ge 1000 ]; then
			DISK_READ_TEST_AVG=$(awk -v a="$DISK_READ_TEST_AVG" 'BEGIN { print a / 1000 }')
			DISK_READ_TEST_UNIT="GB/s"
		else
			DISK_READ_TEST_UNIT="MB/s"
		fi

		# print dd sequential disk speed test results
		echo -e
		echo -e "dd Sequential Disk Speed Tests:"
		echo -e "---------------------------------"
		printf "%-6s | %-6s %-4s | %-6s %-4s | %-6s %-4s | %-6s %-4s\n" "" "Test 1" "" "Test 2" ""  "Test 3" "" "Avg" ""
		printf "%-6s | %-6s %-4s | %-6s %-4s | %-6s %-4s | %-6s %-4s\n"
		printf "%-6s | %-11s | %-11s | %-11s | %-6.2f %-4s\n" "Write" "${DISK_WRITE_TEST_RES[0]}" "${DISK_WRITE_TEST_RES[1]}" "${DISK_WRITE_TEST_RES[2]}" "${DISK_WRITE_TEST_AVG}" "${DISK_WRITE_TEST_UNIT}" 
		printf "%-6s | %-11s | %-11s | %-11s | %-6.2f %-4s\n" "Read" "${DISK_READ_TEST_RES[0]}" "${DISK_READ_TEST_RES[1]}" "${DISK_READ_TEST_RES[2]}" "${DISK_READ_TEST_AVG}" "${DISK_READ_TEST_UNIT}" 
	else # fio tests completed successfully, print results
		[[ ! -z $JSON ]] && JSON_RESULT+=',"fio":['
		DISK_RESULTS_NUM=$(expr ${#DISK_RESULTS[@]} / 6)
		DISK_COUNT=0

		# print disk speed test results
		echo -e "fio Disk Speed Tests (Mixed R/W 50/50):"
		echo -e "---------------------------------"

		while [ $DISK_COUNT -lt $DISK_RESULTS_NUM ] ; do
			if [ $DISK_COUNT -gt 0 ]; then printf "%-10s | %-20s | %-20s\n"; fi
			printf "%-10s | %-11s %8s | %-11s %8s\n" "Block Size" "${BLOCK_SIZES[DISK_COUNT]}" "(IOPS)" "${BLOCK_SIZES[DISK_COUNT+1]}" "(IOPS)"
			printf "%-10s | %-11s %8s | %-11s %8s\n" "  ------" "---" "---- " "----" "---- "
			printf "%-10s | %-11s %8s | %-11s %8s\n" "Read" "${DISK_RESULTS[DISK_COUNT*6+1]}" "(${DISK_RESULTS[DISK_COUNT*6+4]})" "${DISK_RESULTS[(DISK_COUNT+1)*6+1]}" "(${DISK_RESULTS[(DISK_COUNT+1)*6+4]})"
			printf "%-10s | %-11s %8s | %-11s %8s\n" "Write" "${DISK_RESULTS[DISK_COUNT*6+2]}" "(${DISK_RESULTS[DISK_COUNT*6+5]})" "${DISK_RESULTS[(DISK_COUNT+1)*6+2]}" "(${DISK_RESULTS[(DISK_COUNT+1)*6+5]})"
			printf "%-10s | %-11s %8s | %-11s %8s\n" "Total" "${DISK_RESULTS[DISK_COUNT*6]}" "(${DISK_RESULTS[DISK_COUNT*6+3]})" "${DISK_RESULTS[(DISK_COUNT+1)*6]}" "(${DISK_RESULTS[(DISK_COUNT+1)*6+3]})"
			if [ ! -z $JSON ]; then
				JSON_RESULT+='{"bs":"'${BLOCK_SIZES[DISK_COUNT]}'","speed_r":'${DISK_RESULTS_RAW[DISK_COUNT*6+1]}',"iops_r":'${DISK_RESULTS_RAW[DISK_COUNT*6+4]}
				JSON_RESULT+=',"speed_w":'${DISK_RESULTS_RAW[DISK_COUNT*6+2]}',"iops_w":'${DISK_RESULTS_RAW[DISK_COUNT*6+5]}',"speed_rw":'${DISK_RESULTS_RAW[DISK_COUNT*6]}
				JSON_RESULT+=',"iops_rw":'${DISK_RESULTS_RAW[DISK_COUNT*6+3]}'},'
				JSON_RESULT+='{"bs":"'${BLOCK_SIZES[DISK_COUNT+1]}'","speed_r":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6+1]}',"iops_r":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6+4]}
				JSON_RESULT+=',"speed_w":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6+2]}',"iops_w":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6+5]}',"speed_rw":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6]}
				JSON_RESULT+=',"iops_rw":'${DISK_RESULTS_RAW[(DISK_COUNT+1)*6+3]}'},'
			fi
			DISK_COUNT=$(expr $DISK_COUNT + 2)
		done
		[[ ! -z $JSON ]] && JSON_RESULT=${JSON_RESULT::${#JSON_RESULT}-1} && JSON_RESULT+=']'
	fi
fi

# iperf_test
# Purpose: This method is designed to test the network performance of the host by executing an
#          iperf3 test to/from the public iperf server passed to the function. Both directions 
#          (send and receive) are tested.
# Parameters:
#          1. URL - URL/domain name of the iperf server
#          2. PORTS - the range of ports on which the iperf server operates
#          3. HOST - the friendly name of the iperf server host/owner
#          4. FLAGS - any flags that should be passed to the iperf command
function iperf_test {
	URL=$1
	PORTS=$2
	HOST=$3
	FLAGS=$4
	
	# attempt the iperf send test 3 times, allowing for a slot to become available on the
	#   server or to throw out any bad/error results
	I=1
	while [ $I -le 3 ]
	do
		echo -en "Performing $MODE iperf3 send test to $HOST (Attempt #$I of 3)..."
		# select a random iperf port from the range provided
		PORT=`shuf -i $PORTS -n 1`
		# run the iperf test sending data from the host to the iperf server; includes
		#   a timeout of 15s in case the iperf server is not responding; uses 8 parallel
		#   threads for the network test
		IPERF_RUN_SEND="$(timeout 15 $IPERF_CMD $FLAGS -c $URL -p $PORT -P 8 2> /dev/null)"
		# check if iperf exited cleanly and did not return an error
		if [[ "$IPERF_RUN_SEND" == *"receiver"* && "$IPERF_RUN_SEND" != *"error"* ]]; then
			# test did not result in an error, parse speed result
			SPEED=$(echo "${IPERF_RUN_SEND}" | grep SUM | grep receiver | awk '{ print $6 }')
			# if speed result is blank or bad (0.00), rerun, otherwise set counter to exit loop
			[[ -z $SPEED || "$SPEED" == "0.00" ]] && I=$(( $I + 1 )) || I=11
		else
			# if iperf server is not responding, set counter to exit, otherwise increment, sleep, and rerun
			[[ "$IPERF_RUN_SEND" == *"unable to connect"* ]] && I=11 || I=$(( $I + 1 )) && sleep 2
		fi
		echo -en "\r\033[0K"
	done

	# small sleep necessary to give iperf server a breather to get ready for a new test
	sleep 1

	# attempt the iperf receive test 3 times, allowing for a slot to become available on
	#   the server or to throw out any bad/error results
	J=1
	while [ $J -le 3 ]
	do
		echo -n "Performing $MODE iperf3 recv test from $HOST (Attempt #$J of 3)..."
		# select a random iperf port from the range provided
		PORT=`shuf -i $PORTS -n 1`
		# run the iperf test receiving data from the iperf server to the host; includes
		#   a timeout of 15s in case the iperf server is not responding; uses 8 parallel
		#   threads for the network test
		IPERF_RUN_RECV="$(timeout 15 $IPERF_CMD $FLAGS -c $URL -p $PORT -P 8 -R 2> /dev/null)"
		# check if iperf exited cleanly and did not return an error
		if [[ "$IPERF_RUN_RECV" == *"receiver"* && "$IPERF_RUN_RECV" != *"error"* ]]; then
			# test did not result in an error, parse speed result
			SPEED=$(echo "${IPERF_RUN_RECV}" | grep SUM | grep receiver | awk '{ print $6 }')
			# if speed result is blank or bad (0.00), rerun, otherwise set counter to exit loop
			[[ -z $SPEED || "$SPEED" == "0.00" ]] && J=$(( $J + 1 )) || J=11
		else
			# if iperf server is not responding, set counter to exit, otherwise increment, sleep, and rerun
			[[ "$IPERF_RUN_RECV" == *"unable to connect"* ]] && J=11 || J=$(( $J + 1 )) && sleep 2
		fi
		echo -en "\r\033[0K"
	done

	# parse the resulting send and receive speed results
	IPERF_SENDRESULT="$(echo "${IPERF_RUN_SEND}" | grep SUM | grep receiver)"
	IPERF_RECVRESULT="$(echo "${IPERF_RUN_RECV}" | grep SUM | grep receiver)"
}

# launch_iperf
# Purpose: This method is designed to facilitate the execution of iperf network speed tests to
#          each public iperf server in the iperf server locations array.
# Parameters:
#          1. MODE - indicates the type of iperf tests to run (IPv4 or IPv6)
function launch_iperf {
	MODE=$1
	[[ "$MODE" == *"IPv6"* ]] && IPERF_FLAGS="-6" || IPERF_FLAGS="-4"

	# print iperf3 network speed results as they are completed
	echo -e
	echo -e "iperf3 Network Speed Tests ($MODE):"
	echo -e "---------------------------------"
	printf "%-15s | %-25s | %-15s | %-15s\n" "Provider" "Location (Link)" "Send Speed" "Recv Speed"
	printf "%-15s | %-25s | %-15s | %-15s\n"
	
	# loop through iperf locations array to run iperf test using each public iperf server
	for (( i = 0; i < IPERF_LOCS_NUM; i++ )); do
		# test if the current iperf location supports the network mode being tested (IPv4/IPv6)
		if [[ "${IPERF_LOCS[i*5+4]}" == *"$MODE"* ]]; then
			# call the iperf_test function passing the required parameters
			iperf_test "${IPERF_LOCS[i*5]}" "${IPERF_LOCS[i*5+1]}" "${IPERF_LOCS[i*5+2]}" "$IPERF_FLAGS"
			# parse the send and receive speed results
			IPERF_SENDRESULT_VAL=$(echo $IPERF_SENDRESULT | awk '{ print $6 }')
			IPERF_SENDRESULT_UNIT=$(echo $IPERF_SENDRESULT | awk '{ print $7 }')
			IPERF_RECVRESULT_VAL=$(echo $IPERF_RECVRESULT | awk '{ print $6 }')
			IPERF_RECVRESULT_UNIT=$(echo $IPERF_RECVRESULT | awk '{ print $7 }')
			# if the results are blank, then the server is "busy" and being overutilized
			[[ -z $IPERF_SENDRESULT_VAL || "$IPERF_SENDRESULT_VAL" == *"0.00"* ]] && IPERF_SENDRESULT_VAL="busy" && IPERF_SENDRESULT_UNIT=""
			[[ -z $IPERF_RECVRESULT_VAL || "$IPERF_RECVRESULT_VAL" == *"0.00"* ]] && IPERF_RECVRESULT_VAL="busy" && IPERF_RECVRESULT_UNIT=""
			# print the speed results for the iperf location currently being evaluated
			printf "%-15s | %-25s | %-15s | %-15s\n" "${IPERF_LOCS[i*5+2]}" "${IPERF_LOCS[i*5+3]}" "$IPERF_SENDRESULT_VAL $IPERF_SENDRESULT_UNIT" "$IPERF_RECVRESULT_VAL $IPERF_RECVRESULT_UNIT"
			if [ ! -z $JSON ]; then
				JSON_RESULT+='{"mode":"'$MODE'","provider":"'${IPERF_LOCS[i*5+2]}'","loc":"'${IPERF_LOCS[i*5+3]}
				JSON_RESULT+='","send":"'$IPERF_SENDRESULT_VAL' '$IPERF_SENDRESULT_UNIT'","recv":"'$IPERF_RECVRESULT_VAL' '$IPERF_RECVRESULT_UNIT'"},'
			fi
		fi
	done
}

# # if the skip iperf flag was set, skip the network performance test, otherwise test network performance
# if [ -z "$SKIP_IPERF" ]; then

# 	if [[ -z "$PREFER_BIN" && ! -z "$LOCAL_IPERF" ]]; then # local iperf has been detected, use instead of pre-compiled binary
# 		IPERF_CMD=iperf3
# 	else
# 		# create a temp directory to house the required iperf binary and library
# 		IPERF_PATH=$YABS_PATH/iperf
# 		mkdir -p $IPERF_PATH

# 		# download iperf3 binary
# 		if [[ ! -z $LOCAL_CURL ]]; then
# 			curl -s --connect-timeout 5 --retry 5 --retry-delay 0 https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_$ARCH -o $IPERF_PATH/iperf3
# 		else
# 			wget -q -T 5 -t 5 -w 0 https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/bin/iperf/iperf3_$ARCH -O $IPERF_PATH/iperf3
# 		fi

# 		if [ ! -f "$IPERF_PATH/iperf3" ]; then # ensure iperf3 binary downloaded successfully
# 			IPERF_DL_FAIL=True
# 		else
# 			chmod +x $IPERF_PATH/iperf3
# 			IPERF_CMD=$IPERF_PATH/iperf3
# 		fi
# 	fi
	
# 	# array containing all currently available iperf3 public servers to use for the network test
# 	# format: "1" "2" "3" "4" "5" \
# 	#   1. domain name of the iperf server
# 	#   2. range of ports that the iperf server is running on (lowest-highest)
# 	#   3. friendly name of the host/owner of the iperf server
# 	#   4. location and advertised speed link of the iperf server
# 	#   5. network modes supported by the iperf server (IPv4 = IPv4-only, IPv4|IPv6 = IPv4 + IPv6, etc.)
# 	IPERF_LOCS=( \
# 		"lon.speedtest.clouvider.net" "5200-5209" "Clouvider" "London, UK (10G)" "IPv4|IPv6" \
# 		"ping.online.net" "5200-5209" "Online.net" "Paris, FR (10G)" "IPv4" \
# 		"ping6.online.net" "5200-5209" "Online.net" "Paris, FR (10G)" "IPv6" \
# 		"speedtest-nl-oum.hybula.net" "5201-5206" "Hybula" "The Netherlands (40G)" "IPv4|IPv6" \
# 		"speedtest.uztelecom.uz" "5200-5207" "Uztelecom" "Tashkent, UZ (10G)" "IPv4|IPv6" \
# 		"nyc.speedtest.clouvider.net" "5200-5209" "Clouvider" "NYC, NY, US (10G)" "IPv4|IPv6" \
# 		"dal.speedtest.clouvider.net" "5200-5209" "Clouvider" "Dallas, TX, US (10G)" "IPv4|IPv6" \
# 		"la.speedtest.clouvider.net" "5200-5209" "Clouvider" "Los Angeles, CA, US (10G)" "IPv4|IPv6" \
# 	)

# 	# if the "REDUCE_NET" flag is activated, then do a shorter iperf test with only three locations
# 	# (Clouvider London, Clouvider NYC, and Online.net France)
# 	if [ ! -z "$REDUCE_NET" ]; then
# 		IPERF_LOCS=( \
# 			"lon.speedtest.clouvider.net" "5200-5209" "Clouvider" "London, UK (10G)" "IPv4|IPv6" \
# 			"ping.online.net" "5200-5209" "Online.net" "Paris, FR (10G)" "IPv4" \
# 			"ping6.online.net" "5200-5209" "Online.net" "Paris, FR (10G)" "IPv6" \
# 			"nyc.speedtest.clouvider.net" "5200-5209" "Clouvider" "NYC, NY, US (10G)" "IPv4|IPv6" \
# 		)
# 	fi
	
# 	# get the total number of iperf locations (total array size divided by 5 since each location has 5 elements)
# 	IPERF_LOCS_NUM=${#IPERF_LOCS[@]}
# 	IPERF_LOCS_NUM=$((IPERF_LOCS_NUM / 5))
	
# 	if [ -z "$IPERF_DL_FAIL" ]; then
# 		[[ ! -z $JSON ]] && JSON_RESULT+=',"iperf":['
# 		# check if the host has IPv4 connectivity, if so, run iperf3 IPv4 tests
# 		[ ! -z "$IPV4_CHECK" ] && launch_iperf "IPv4"
# 		# check if the host has IPv6 connectivity, if so, run iperf3 IPv6 tests
# 		[ ! -z "$IPV6_CHECK" ] && launch_iperf "IPv6"
# 		[[ ! -z $JSON ]] && JSON_RESULT=${JSON_RESULT::${#JSON_RESULT}-1} && JSON_RESULT+=']'
# 	else
# 		echo -e "\niperf3 binary download failed. Skipping iperf network tests..."
# 	fi
# fi

# launch_geekbench
# Purpose: This method is designed to run the Primate Labs' Geekbench 4/5 Cross-Platform Benchmark utility
# Parameters:
#          1. VERSION - indicates which Geekbench version to run
function launch_geekbench {
	VERSION=$1

	# create a temp directory to house all geekbench files
	GEEKBENCH_PATH=$YABS_PATH/geekbench_$VERSION
	mkdir -p $GEEKBENCH_PATH

	# check for curl vs wget
	[[ ! -z $LOCAL_CURL ]] && DL_CMD="curl -s" || DL_CMD="wget -qO-"

	if [[ $VERSION == *4* && ($ARCH = *aarch64* || $ARCH = *arm*) ]]; then
		echo -e "\nARM architecture not supported by Geekbench 4, use Geekbench 5."
	elif [[ $VERSION == *4* && $ARCH != *aarch64* && $ARCH != *arm* ]]; then # Geekbench v4
		echo -en "\nRunning GB4 benchmark test... *cue elevator music*"
		# download the latest Geekbench 4 tarball and extract to geekbench temp directory
		$DL_CMD https://cdn.geekbench.com/Geekbench-4.4.4-Linux.tar.gz  | tar xz --strip-components=1 -C $GEEKBENCH_PATH &>/dev/null

		if [[ "$ARCH" == *"x86"* ]]; then
			# check if geekbench file exists
			if test -f "geekbench.license"; then
				$GEEKBENCH_PATH/geekbench_x86_32 --unlock `cat geekbench.license` > /dev/null 2>&1
			fi

			# run the Geekbench 4 test and grep the test results URL given at the end of the test
			GEEKBENCH_TEST=$($GEEKBENCH_PATH/geekbench_x86_32 --upload 2>/dev/null | grep "https://browser")
		else
			# check if geekbench file exists
			if test -f "geekbench.license"; then
				$GEEKBENCH_PATH/geekbench4 --unlock `cat geekbench.license` > /dev/null 2>&1
			fi
			
			# run the Geekbench 4 test and grep the test results URL given at the end of the test
			GEEKBENCH_TEST=$($GEEKBENCH_PATH/geekbench4 --upload 2>/dev/null | grep "https://browser")
		fi
	fi

	if [[ $VERSION == *5* ]]; then # Geekbench v5
		if [[ $ARCH = *x86* && $GEEKBENCH_4 == *False* ]]; then # don't run Geekbench 5 if on 32-bit arch
			echo -e "\nGeekbench 5 cannot run on 32-bit architectures. Re-run with -4 flag to use"
			echo -e "Geekbench 4, which can support 32-bit architectures. Skipping Geekbench 5."
		elif [[ $ARCH = *x86* && $GEEKBENCH_4 == *True* ]]; then
			echo -e "\nGeekbench 5 cannot run on 32-bit architectures. Skipping test."
		else
			echo -en "\nRunning GB5 benchmark test... *cue elevator music*"
			# download the latest Geekbench 5 tarball and extract to geekbench temp directory
			if [[ $ARCH = *aarch64* || $ARCH = *arm* ]]; then
				$DL_CMD https://cdn.geekbench.com/Geekbench-5.4.4-LinuxARMPreview.tar.gz  | tar xz --strip-components=1 -C $GEEKBENCH_PATH &>/dev/null
			else
				$DL_CMD https://cdn.geekbench.com/Geekbench-5.4.5-Linux.tar.gz | tar xz --strip-components=1 -C $GEEKBENCH_PATH &>/dev/null
			fi

			# check if geekbench file exists
			if test -f "geekbench.license"; then
				$GEEKBENCH_PATH/geekbench5 --unlock `cat geekbench.license` > /dev/null 2>&1
			fi

			GEEKBENCH_TEST=$($GEEKBENCH_PATH/geekbench5 --upload 2>/dev/null | grep "https://browser")
		fi
	fi

	# ensure the test ran successfully
	if [ -z "$GEEKBENCH_TEST" ]; then
		if [[ -z "$IPV4_CHECK" ]]; then
			# Geekbench test failed to download because host lacks IPv4 (cdn.geekbench.com = IPv4 only)
			echo -e "\r\033[0KGeekbench releases can only be downloaded over IPv4. FTP the Geekbench files and run manually."
		elif [[ $ARCH != *x86* ]]; then
			# if the Geekbench test failed for any reason, exit cleanly and print error message
			echo -e "\r\033[0KGeekbench $VERSION test failed. Run manually to determine cause."
		fi
	else
		# if the Geekbench test succeeded, parse the test results URL
		GEEKBENCH_URL=$(echo -e $GEEKBENCH_TEST | head -1)
		GEEKBENCH_URL_CLAIM=$(echo $GEEKBENCH_URL | awk '{ print $2 }')
		GEEKBENCH_URL=$(echo $GEEKBENCH_URL | awk '{ print $1 }')
		# sleep a bit to wait for results to be made available on the geekbench website
		sleep 20
		# parse the public results page for the single and multi core geekbench scores
		[[ $VERSION == *5* ]] && GEEKBENCH_SCORES=$($DL_CMD $GEEKBENCH_URL | grep "div class='score'") ||
			GEEKBENCH_SCORES=$($DL_CMD $GEEKBENCH_URL | grep "span class='score'")
		GEEKBENCH_SCORES_SINGLE=$(echo $GEEKBENCH_SCORES | awk -v FS="(>|<)" '{ print $3 }')
		GEEKBENCH_SCORES_MULTI=$(echo $GEEKBENCH_SCORES | awk -v FS="(>|<)" '{ print $7 }')
	
		# print the Geekbench results
		echo -en "\r\033[0K"
		echo -e "Geekbench $VERSION Benchmark Test:"
		echo -e "---------------------------------"
		printf "%-15s | %-30s\n" "Test" "Value"
		printf "%-15s | %-30s\n"
		printf "%-15s | %-30s\n" "Single Core" "$GEEKBENCH_SCORES_SINGLE"
		printf "%-15s | %-30s\n" "Multi Core" "$GEEKBENCH_SCORES_MULTI"
		printf "%-15s | %-30s\n" "Full Test" "$GEEKBENCH_URL"

		if [ ! -z $JSON ]; then
			JSON_RESULT+='{"version":'$VERSION',"single":'$GEEKBENCH_SCORES_SINGLE',"multi":'$GEEKBENCH_SCORES_MULTI
			JSON_RESULT+=',"url":"'$GEEKBENCH_URL'"},'
		fi

		# write the geekbench claim URL to a file so the user can add the results to their profile (if desired)
		[ ! -z "$GEEKBENCH_URL_CLAIM" ] && echo -e "$GEEKBENCH_URL_CLAIM" >> geekbench_claim.url 2> /dev/null
	fi
}

# if the skip geekbench flag was set, skip the system performance test, otherwise test system performance
if [ -z "$SKIP_GEEKBENCH" ]; then
	[[ ! -z $JSON ]] && JSON_RESULT+=',"geekbench":['
	if [[ $GEEKBENCH_4 == *True* ]]; then
		launch_geekbench 4
	fi

	if [[ $GEEKBENCH_5 == *True* ]]; then
		launch_geekbench 5
	fi
	[[ ! -z $JSON ]] && JSON_RESULT=${JSON_RESULT::${#JSON_RESULT}-1} && JSON_RESULT+=']'
fi

# finished all tests, clean up all YABS files and exit
echo -e
rm -rf $YABS_PATH

if [[ ! -z $JSON ]]; then
	JSON_RESULT+='}'

	# write json results to file
	if [[ $JSON = *w* ]]; then
		echo $JSON_RESULT > $JSON_FILE
	fi

	# send json results
	if [[ $JSON = *s* ]]; then
		IFS=',' read -r -a JSON_SITES <<< "$JSON_SEND"
		for JSON_SITE in "${JSON_SITES[@]}"
		do
			if [[ ! -z $LOCAL_CURL ]]; then
				curl -s -H "Content-Type:application/json" -X POST --data ''"$JSON_RESULT"'' $JSON_SITE
			else
				wget -qO- --post-data=''"$JSON_RESULT"'' --header='Content-Type:application/json' $JSON_SITE
			fi
		done
	fi

	# print json result to screen
	if [[ $JSON = *j* ]]; then
		echo -e
		echo $JSON_RESULT
	fi
fi

# reset locale settings
unset LC_ALL


###################
### 流媒体
###################

shopt -s expand_aliases
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"

while getopts ":I:M:EX:" optname; do
    case "$optname" in
    "I")
        iface="$OPTARG"
        useNIC="--interface $iface"
        ;;
    "M")
        if [[ "$OPTARG" == "4" ]]; then
            NetworkType=4
        elif [[ "$OPTARG" == "6" ]]; then
            NetworkType=6
        fi
        ;;
    "E")
        language="e"
        ;;
    "X")
        XIP="$OPTARG"
        xForward="--header X-Forwarded-For:$XIP"
        ;;
    ":")
        echo "Unknown error while processing options"
        exit 1
        ;;
    esac

done

if [ -z "$iface" ]; then
    useNIC=""
fi

if [ -z "$XIP" ]; then
    xForward=""
fi

if ! mktemp -u --suffix=RRC &>/dev/null; then
    is_busybox=1
fi

UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_Dalvik="Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)"
WOWOW_Cookie=$(curl -s "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | awk 'NR==3')
TVer_Cookie="Accept: application/json;pk=BCpkADawqM0_rzsjsYbC1k1wlJLU4HiAtfzjxdUmfvvLUQB-Ax6VA-p-9wOEZbCEm3u95qq2Y1CQQW1K9tPaMma9iAqUqhpISCmyXrgnlpx9soEmoVNuQpiyGsTpePGumWxSs1YoKziYB6Wz"

countRunTimes() {
    if [ "$is_busybox" == 1 ]; then
        count_file=$(mktemp)
    else
        count_file=$(mktemp --suffix=RRC)
    fi
    RunTimes=$(curl -s --max-time 10 "https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fcheck.unclock.media&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=visit&edge_flat=false" >"${count_file}")
    TodayRunTimes=$(cat "${count_file}" | tail -3 | head -n 1 | awk '{print $5}')
    TotalRunTimes=$(($(cat "${count_file}" | tail -3 | head -n 1 | awk '{print $7}') + 2527395))
}
countRunTimes

checkOS() {
    ifTermux=$(echo $PWD | grep termux)
    ifMacOS=$(uname -a | grep Darwin)
    if [ -n "$ifTermux" ]; then
        os_version=Termux
        is_termux=1
    elif [ -n "$ifMacOS" ]; then
        os_version=MacOS
        is_macos=1
    else
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    fi

    if [[ "$os_version" == "2004" ]] || [[ "$os_version" == "10" ]] || [[ "$os_version" == "11" ]]; then
        is_windows=1
        ssll="-k --ciphers DEFAULT@SECLEVEL=1"
    fi

    if [ "$(which apt 2>/dev/null)" ]; then
        InstallMethod="apt"
        is_debian=1
    elif [ "$(which dnf 2>/dev/null)" ] || [ "$(which yum 2>/dev/null)" ]; then
        InstallMethod="yum"
        is_redhat=1
    elif [[ "$os_version" == "Termux" ]]; then
        InstallMethod="pkg"
    elif [[ "$os_version" == "MacOS" ]]; then
        InstallMethod="brew"
    fi
}
checkOS

checkCPU() {
    CPUArch=$(uname -m)
    if [[ "$CPUArch" == "aarch64" ]]; then
        arch=_arm64
    elif [[ "$CPUArch" == "i686" ]]; then
        arch=_i686
    elif [[ "$CPUArch" == "arm" ]]; then
        arch=_arm
    elif [[ "$CPUArch" == "x86_64" ]] && [ -n "$ifMacOS" ]; then
        arch=_darwin
    fi
}
checkCPU

checkDependencies() {

    # os_detail=$(cat /etc/os-release 2> /dev/null)

    if ! command -v python &>/dev/null; then
        if command -v python3 &>/dev/null; then
            alias python="python3"
        else
            if [ "$is_debian" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod update >/dev/null 2>&1
                $InstallMethod install python -y >/dev/null 2>&1
            elif [ "$is_redhat" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                if [[ "$os_version" -gt 7 ]]; then
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python3 -y >/dev/null 2>&1
                    alias python="python3"
                else
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python -y >/dev/null 2>&1
                fi

            elif [ "$is_termux" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod update -y >/dev/null 2>&1
                $InstallMethod install python -y >/dev/null 2>&1

            elif [ "$is_macos" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod install python
            fi
        fi
    fi

    if ! command -v dig &>/dev/null; then
        if [ "$is_debian" == 1 ]; then
            echo -e "${Font_Green}Installing dnsutils${Font_Suffix}"
            $InstallMethod update >/dev/null 2>&1
            $InstallMethod install dnsutils -y >/dev/null 2>&1
        elif [ "$is_redhat" == 1 ]; then
            echo -e "${Font_Green}Installing bind-utils${Font_Suffix}"
            $InstallMethod makecache >/dev/null 2>&1
            $InstallMethod install bind-utils -y >/dev/null 2>&1
        elif [ "$is_termux" == 1 ]; then
            echo -e "${Font_Green}Installing dnsutils${Font_Suffix}"
            $InstallMethod update -y >/dev/null 2>&1
            $InstallMethod install dnsutils -y >/dev/null 2>&1
        elif [ "$is_macos" == 1 ]; then
            echo -e "${Font_Green}Installing bind${Font_Suffix}"
            $InstallMethod install bind
        fi
    fi

    if [ "$is_macos" == 1 ]; then
        if ! command -v md5sum &>/dev/null; then
            echo -e "${Font_Green}Installing md5sha1sum${Font_Suffix}"
            $InstallMethod install md5sha1sum
        fi
    fi

}
checkDependencies

local_ipv4=$(curl $useNIC -4 -s --max-time 10 api64.ipify.org)
local_ipv4_asterisk=$(awk -F"." '{print $1"."$2".*.*"}' <<<"${local_ipv4}")
local_ipv6=$(curl $useNIC -6 -s --max-time 20 api64.ipify.org)
local_ipv6_asterisk=$(awk -F":" '{print $1":"$2":"$3":*:*"}' <<<"${local_ipv6}")
local_isp4=$(curl $useNIC -s -4 --max-time 10 --user-agent "${UA_Browser}" "https://api.ip.sb/geoip/${local_ipv4}" | cut -f1 -d"," | cut -f4 -d '"')
local_isp6=$(curl $useNIC -s -6 --max-time 10 --user-agent "${UA_Browser}" "https://api.ip.sb/geoip/${local_ipv6}" | cut -f1 -d"," | cut -f4 -d '"')

ShowRegion() {
    echo -e "${Font_Yellow} ---${1}---${Font_Suffix}"
}

function GameTest_Steam() {
    echo -n -e " Steam Currency:\t\t\t->\c"
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 "https://store.steampowered.com/app/761830" 2>&1 | grep priceCurrency | cut -d '"' -f4)

    if [ ! -n "$result" ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    else
        echo -n -e "\r Steam Currency:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_HBONow() {
    echo -n -e " HBO Now:\t\t\t\t->\c"
    # 尝试获取成功的结果
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 --write-out "%{url_effective}\n" --output /dev/null "https://play.hbonow.com/" 2>&1)
    if [[ "$result" != "curl"* ]]; then
        # 下载页面成功，开始解析跳转
        if [ "${result}" = "https://play.hbonow.com" ] || [ "${result}" = "https://play.hbonow.com/" ]; then
            echo -n -e "\r HBO Now:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        elif [ "${result}" = "http://hbogeo.cust.footprint.net/hbonow/geo.html" ] || [ "${result}" = "http://geocust.hbonow.com/hbonow/geo.html" ]; then
            echo -n -e "\r HBO Now:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        fi
    else
        # 下载页面失败，返回错误代码
        echo -e "\r HBO Now:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    fi
}

# 流媒体解锁测试-动画疯
function MediaUnlockTest_BahamutAnime() {
    echo -n -e " Bahamut Anime:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" --max-time 10 -fsSL "https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=14667" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Bahamut Anime:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'animeSn')
    if [ -n "$result" ]; then
        echo -n -e "\r Bahamut Anime:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r Bahamut Anime:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

# 流媒体解锁测试-哔哩哔哩大陆限定
function MediaUnlockTest_BilibiliChinaMainland() {
    echo -n -e " BiliBili China Mainland Only:\t\t->\c"
    local randsession="$(cat /dev/urandom | head -n 32 | md5sum | head -c 32)"
    # 尝试获取成功的结果
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 "https://api.bilibili.com/pgc/player/web/playurl?avid=82846771&qn=0&type=&otype=json&ep_id=307247&fourk=1&fnver=0&fnval=16&session=${randsession}&module=bangumi" 2>&1)
    if [[ "$result" != "curl"* ]]; then
        local result="$(echo "${result}" | python -m json.tool 2>/dev/null | grep '"code"' | head -1 | awk '{print $2}' | cut -d ',' -f1)"
        if [ "${result}" = "0" ]; then
            echo -n -e "\r BiliBili China Mainland Only:\t\t${Font_Green}Yes${Font_Suffix}\n"
        elif [ "${result}" = "-10403" ]; then
            echo -n -e "\r BiliBili China Mainland Only:\t\t${Font_Red}No${Font_Suffix}\n"
        else
            echo -n -e "\r BiliBili China Mainland Only:\t\t${Font_Red}Failed${Font_Suffix} ${Font_SkyBlue}(${result})${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r BiliBili China Mainland Only:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    fi
}

# 流媒体解锁测试-哔哩哔哩港澳台限定
function MediaUnlockTest_BilibiliHKMCTW() {
    echo -n -e " BiliBili Hongkong/Macau/Taiwan:\t->\c"
    local randsession="$(cat /dev/urandom | head -n 32 | md5sum | head -c 32)"
    # 尝试获取成功的结果
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 "https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1&fnver=0&fnval=16&session=${randsession}&module=bangumi" 2>&1)
    if [[ "$result" != "curl"* ]]; then
        local result="$(echo "${result}" | python -m json.tool 2>/dev/null | grep '"code"' | head -1 | awk '{print $2}' | cut -d ',' -f1)"
        if [ "${result}" = "0" ]; then
            echo -n -e "\r BiliBili Hongkong/Macau/Taiwan:\t${Font_Green}Yes${Font_Suffix}\n"
        elif [ "${result}" = "-10403" ]; then
            echo -n -e "\r BiliBili Hongkong/Macau/Taiwan:\t${Font_Red}No${Font_Suffix}\n"
        else
            echo -n -e "\r BiliBili Hongkong/Macau/Taiwan:\t${Font_Red}Failed${Font_Suffix} ${Font_SkyBlue}(${result})${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r BiliBili Hongkong/Macau/Taiwan:\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    fi
}

# 流媒体解锁测试-哔哩哔哩台湾限定
function MediaUnlockTest_BilibiliTW() {
    echo -n -e " Bilibili Taiwan Only:\t\t\t->\c"
    local randsession="$(cat /dev/urandom | head -n 32 | md5sum | head -c 32)"
    # 尝试获取成功的结果
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsSL --max-time 10 "https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1&fnver=0&fnval=16&session=${randsession}&module=bangumi" 2>&1)
    if [[ "$result" != "curl"* ]]; then
        local result="$(echo "${result}" | python -m json.tool 2>/dev/null | grep '"code"' | head -1 | awk '{print $2}' | cut -d ',' -f1)"
        if [ "${result}" = "0" ]; then
            echo -n -e "\r Bilibili Taiwan Only:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        elif [ "${result}" = "-10403" ]; then
            echo -n -e "\r Bilibili Taiwan Only:\t\t\t${Font_Red}No${Font_Suffix}\n"
        else
            echo -n -e "\r Bilibili Taiwan Only:\t\t\t${Font_Red}Failed${Font_Suffix} ${Font_SkyBlue}(${result})${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r Bilibili Taiwan Only:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    fi
}

# 流媒体解锁测试-Abema.TV
#
function MediaUnlockTest_AbemaTV_IPTest() {
    echo -n -e " Abema.TV:\t\t\t\t->\c"
    #
    local tempresult=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --max-time 10 "https://api.abema.io/v1/ip/check?device=android" 2>&1)
    if [[ "$tempresult" == "000" ]]; then
        echo -n -e "\r Abema.TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --max-time 10 "https://api.abema.io/v1/ip/check?device=android" | python -m json.tool 2>/dev/null | grep isoCountryCode | awk '{print $2}' | cut -f2 -d'"')
    if [ -n "$result" ]; then
        if [[ "$result" == "JP" ]]; then
            echo -n -e "\r Abema.TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        else
            echo -n -e "\r Abema.TV:\t\t\t\t${Font_Yellow}Oversea Only${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r Abema.TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_PCRJP() {
    echo -n -e " Princess Connect Re:Dive Japan:\t->\c"
    # 测试，连续请求两次 (单独请求一次可能会返回35, 第二次开始变成0)
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api-priconne-redive.cygames.jp/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Princess Connect Re:Dive Japan:\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "404" ]; then
        echo -n -e "\r Princess Connect Re:Dive Japan:\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Princess Connect Re:Dive Japan:\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Princess Connect Re:Dive Japan:\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_UMAJP() {
    echo -n -e " Pretty Derby Japan:\t\t\t->\c"
    # 测试，连续请求两次 (单独请求一次可能会返回35, 第二次开始变成0)
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api-umamusume.cygames.jp/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Pretty Derby Japan:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "404" ]; then
        echo -n -e "\r Pretty Derby Japan:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Pretty Derby Japan:\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Pretty Derby Japan:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_WFJP() {
    echo -n -e " World Flipper Japan:\t\t\t->\c"
    # 测试，连续请求两次 (单独请求一次可能会返回35, 第二次开始变成0)
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api.worldflipper.jp/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r World Flipper Japan:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r World Flipper Japan:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r World Flipper Japan:\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r World Flipper Japan:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Kancolle() {
    echo -n -e " Kancolle Japan:\t\t\t->\c"
    # 测试，连续请求两次 (单独请求一次可能会返回35, 第二次开始变成0)
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "http://203.104.209.7/kcscontents/news/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Kancolle Japan:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Kancolle Japan:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Kancolle Japan:\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Kancolle Japan:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_BBCiPLAYER() {
    echo -n -e " BBC iPLAYER:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -fsL --max-time 10 "https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0/mediaset/pc/vpid/bbc_one_london/format/json/jsfunc/JS_callbacks0")
    if [ "${tmpresult}" = "000" ]; then
        echo -n -e "\r BBC iPLAYER:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    if [ -n "$tmpresult" ]; then
        result=$(echo $tmpresult | grep 'geolocation')
        if [ -n "$result" ]; then
            echo -n -e "\r BBC iPLAYER:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        else
            echo -n -e "\r BBC iPLAYER:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        fi
    else
        echo -n -e "\r BBC iPLAYER:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Netflix() {
    echo -n -e " Netflix:\t\t\t\t->\c"
    local result1=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://www.netflix.com/title/81215567" 2>&1)

    if [[ "$result1" == "404" ]]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Yellow}Originals Only${Font_Suffix}\n"
        return
    elif [[ "$result1" == "403" ]]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result1" == "200" ]]; then
        local region=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -fs --max-time 10 --write-out %{redirect_url} --output /dev/null "https://www.netflix.com/title/80018499" | cut -d '/' -f4 | cut -d '-' -f1 | tr [:lower:] [:upper:])
        if [[ ! -n "$region" ]]; then
            region="US"
        fi
        echo -n -e "\r Netflix:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    elif [[ "$result1" == "000" ]]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_DisneyPlus() {
    echo -n -e " Disney+:\t\t\t\t->\c"
    local PreAssertion=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
    if [[ "$PreAssertion" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$PreAssertion" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local assertion=$(echo $PreAssertion | python -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    local PreDisneyCookie=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '1p')
    local disneycookie=$(echo $PreDisneyCookie | sed "s/DISNEYASSERTION/${assertion}/g")
    local TokenContent=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie")
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local fakecontent=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '8p')
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local disneycontent=$(echo $fakecontent | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)
    local previewcheck=$(curl $useNIC $xForward -${1} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://disneyplus.com" | grep preview)
    local isUnabailable=$(echo $previewcheck | grep 'unavailable')
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "JP" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: JP)${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "false" ]] && [ -z "$isUnabailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Yellow}Available For [Disney+ $region] Soon${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [ -n "$isUnavailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    elif [ -z "$region" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Dazn() {
    echo -n -e " Dazn:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} -sS --max-time 10 -X POST -H "Content-Type: application/json" -d '{"LandingPageKey":"generic","Languages":"zh-CN,zh,en","Platform":"web","PlatformAttributes":{},"Manufacturer":"","PromoCode":"","Version":"2"}' "https://startup.core.indazn.com/misl/v5/Startup" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    isAllowed=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'isAllowed' | awk '{print $2}' | cut -f1 -d',')
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep '"GeolocatedCountry":' | awk '{print $2}' | cut -f2 -d'"')

    if [[ "$isAllowed" == "true" ]]; then
        local CountryCode=$(echo $result | tr [:lower:] [:upper:])
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Green}Yes (Region: ${CountryCode})${Font_Suffix}\n"
        return
    elif [[ "$isAllowed" == "false" ]]; then
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}Unsupport${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_HuluJP() {
    echo -n -e " Hulu Japan:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://id.hulu.jp" | grep 'restrict')

    if [ -n "$result" ]; then
        echo -n -e "\r Hulu Japan:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Hulu Japan:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Hulu Japan:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_MyTVSuper() {
    echo -n -e " MyTVSuper:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -s -${1} --max-time 10 "https://www.mytvsuper.com/api/auth/getSession/self/" | python -m json.tool 2>/dev/null | grep 'region' | awk '{print $2}')

    if [[ "$result" == "1" ]]; then
        echo -n -e "\r MyTVSuper:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r MyTVSuper:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r MyTVSuper:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_NowE() {
    echo -n -e " Now E:\t\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 -X POST -H "Content-Type: application/json" -d '{"contentId":"202105121370235","contentType":"Vod","pin":"","deviceId":"W-60b8d30a-9294-d251-617b-c12f9d0c","deviceType":"WEB"}' "https://webtvapi.nowe.com/16/1/getVodURL" | python -m json.tool 2>/dev/null | grep 'responseCode' | awk '{print $2}' | cut -f2 -d'"' 2>&1)

    if [[ "$result" == "SUCCESS" ]]; then
        echo -n -e "\r Now E:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "PRODUCT_INFORMATION_INCOMPLETE" ]]; then
        echo -n -e "\r Now E:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "GEO_CHECK_FAIL" ]]; then
        echo -n -e "\r Now E:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Now E:\t\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Now E:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_ViuTV() {
    echo -n -e " Viu.TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 -X POST -H "Content-Type: application/json" -d '{"callerReferenceNo":"20210726112323","contentId":"099","contentType":"Channel","channelno":"099","mode":"prod","deviceId":"29b3cb117a635d5b56","deviceType":"ANDROID_WEB"}' "https://api.viu.now.com/p8/3/getLiveURL")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Viu.TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'responseCode' | awk '{print $2}' | cut -f2 -d'"')
    if [[ "$result" == "SUCCESS" ]]; then
        echo -n -e "\r Viu.TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "GEO_CHECK_FAIL" ]]; then
        echo -n -e "\r Viu.TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Viu.TV:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_unext() {
    echo -n -e " U-NEXT:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} -s --max-time 10 "https://video-api.unext.jp/api/1/player?entity%5B%5D=playlist_url&episode_code=ED00148814&title_code=SID0028118&keyonly_flg=0&play_mode=caption&bitrate_low=1500" | python -m json.tool 2>/dev/null | grep 'result_status' | awk '{print $2}' | cut -d ',' -f1)
    if [ -n "$result" ]; then
        if [[ "$result" == "475" ]]; then
            echo -n -e "\r U-NEXT:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        elif [[ "$result" == "200" ]]; then
            echo -n -e "\r U-NEXT:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        elif [[ "$result" == "467" ]]; then
            echo -n -e "\r U-NEXT:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        else
            echo -n -e "\r U-NEXT:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r U-NEXT:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Paravi() {
    echo -n -e " Paravi:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} -Ss --max-time 10 -H "Content-Type: application/json" -d '{"meta_id":17414,"vuid":"3b64a775a4e38d90cc43ea4c7214702b","device_code":1,"app_id":1}' "https://api.paravi.jp/api/v1/playback/auth" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Paravi:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep type | awk '{print $2}' | cut -f2 -d'"')
    if [[ "$result" == "Forbidden" ]]; then
        echo -n -e "\r Paravi:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "Unauthorized" ]]; then
        echo -n -e "\r Paravi:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_wowow() {
    echo -n -e " WOWOW:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -Ss --max-time 10 -b "${WOWOW_Cookie}" -H "x-wod-app-version: 91.0.4472.106" -H "x-wod-model: Chrome" -H "x-wod-os: Windows" -H "x-wod-os-version: 10" -H "x-wod-platform: Windows" "https://wod.wowow.co.jp/api/streaming/url?contentId=&channel=Live" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r WOWOW:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    checkfailed=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep code | cut -f4 -d'"')
    if [[ "$checkfailed" == "E0004" ]]; then
        echo -n -e "\r WOWOW:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$checkfailed" == "E5101" ]]; then
        echo -n -e "\r WOWOW:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r WOWOW:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_TVer() {
    echo -n -e " TVer:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -Ss --max-time 10 -H "${TVer_Cookie}" "https://edge.api.brightcove.com/playback/v1/accounts/5102072605001/videos/ref%3Akaguyasama_01 " 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r TVer:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep error_subcode | cut -f4 -d'"')
    if [[ "$result" == "CLIENT_GEO" ]]; then
        echo -n -e "\r TVer:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$result" ] && [ -n "$tmpresult" ]; then
        echo -n -e "\r TVer:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r TVer:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_HamiVideo() {
    echo -n -e " Hami Video:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -Ss --max-time 10 "https://hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Hami Video:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    checkfailed=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'code' | cut -f4 -d'"')
    if [[ "$checkfailed" == "06001-106" ]]; then
        echo -n -e "\r Hami Video:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$checkfailed" == "06001-107" ]]; then
        echo -n -e "\r Hami Video:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Hami Video:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_4GTV() {
    echo -n -e " 4GTV.TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -sS --max-time 10 -X POST -d 'value=D33jXJ0JVFkBqV%2BZSi1mhPltbejAbPYbDnyI9hmfqjKaQwRQdj7ZKZRAdb16%2FRUrE8vGXLFfNKBLKJv%2BfDSiD%2BZJlUa5Msps2P4IWuTrUP1%2BCnS255YfRadf%2BKLUhIPj' "https://api2.4gtv.tv//Vod/GetVodUrl3" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r 4GTV.TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    checkfailed=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'Success' | awk '{print $2}' | cut -f1 -d',')
    if [[ "$checkfailed" == "false" ]]; then
        echo -n -e "\r 4GTV.TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$checkfailed" == "true" ]]; then
        echo -n -e "\r 4GTV.TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r 4GTV.TV:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_SlingTV() {
    echo -n -e " Sling TV:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://www.sling.com/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Sling TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Sling TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Sling TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Sling TV:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_PlutoTV() {
    echo -n -e " Pluto TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://pluto.tv/" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Pluto TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep 'thanks-for-watching')
    if [ -n "$result" ]; then
        echo -n -e "\r Pluto TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Pluto TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Pluto TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_HBOMax() {
    echo -n -e " HBO Max:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.hbomax.com/" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local isUnavailable=$(echo $tmpresult | grep 'geo-availability')
    local region=$(echo $tmpresult | cut -f4 -d"/" | tr [:lower:] [:upper:])
    if [ -n "$isUnavailable" ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$isUnavailable" ] && [ -n "$region" ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    elif [ -z "$isUnavailable" ] && [ -z "$region" ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Channel4() {
    echo -n -e " Channel 4:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://ais.channel4.com/simulcast/C4?client=c4" | grep 'status' | cut -f2 -d'"')

    if [[ "$result" == "ERROR" ]]; then
        echo -n -e "\r Channel 4:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "OK" ]]; then
        echo -n -e "\r Channel 4:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Channel 4:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_ITVHUB() {
    echo -n -e " ITV Hub:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://simulcast.itv.com/playlist/itvonline/ITV")
    if [ "$result" = "000" ]; then
        echo -n -e "\r ITV Hub:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "404" ]; then
        echo -n -e "\r ITV Hub:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r ITV Hub:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r ITV Hub:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_iQYI_Region() {
    echo -n -e " iQyi Oversea Region:\t\t\t->\c"
    curl $useNIC $xForward -${1} ${ssll} -s -I --max-time 10 "https://www.iq.com/" >~/iqiyi

    if [ $? -eq 1 ]; then
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    result=$(cat ~/iqiyi | grep 'mod=' | awk '{print $2}' | cut -f2 -d'=' | cut -f1 -d';')
    rm ~/iqiyi >/dev/null 2>&1

    if [ -n "$result" ]; then
        if [[ "$result" == "ntw" ]]; then
            result=TW
            echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
            return
        else
            result=$(echo $result | tr [:lower:] [:upper:])
            echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_HuluUS() {
    if [[ "$1" == "4" ]]; then
        curl $useNIC $xForward -fsL -o ./Hulu4.sh.x https://github.com/lmc999/RegionRestrictionCheck/raw/main/binary/Hulu4${arch}.sh.x >/dev/null 2>&1
        chmod +x ./Hulu4.sh.x
        ./Hulu4.sh.x >/dev/null 2>&1
    elif [[ "$1" == "6" ]]; then
        curl $useNIC $xForward -fsL -o ./Hulu6.sh.x https://github.com/lmc999/RegionRestrictionCheck/raw/main/binary/Hulu6${arch}.sh.x >/dev/null 2>&1
        chmod +x ./Hulu6.sh.x
        ./Hulu6.sh.x >/dev/null 2>&1
    fi

    local result=$?

    echo -n -e " Hulu:\t\t\t\t\t->\c"
    if [[ "$result" == "1" ]]; then
        echo -n -e "\r Hulu:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    elif [[ "$result" == "0" ]]; then
        echo -n -e "\r Hulu:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [[ "$result" == "10" ]]; then
        echo -n -e "\r Hulu:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
    rm -rf ./*.sh.x
}

function MediaUnlockTest_encoreTVB() {
    echo -n -e " encoreTVB:\t\t\t\t->\c"
    tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 -H "Accept: application/json;pk=BCpkADawqM2Gpjj8SlY2mj4FgJJMfUpxTNtHWXOItY1PvamzxGstJbsgc-zFOHkCVcKeeOhPUd9MNHEGJoVy1By1Hrlh9rOXArC5M5MTcChJGU6maC8qhQ4Y8W-QYtvi8Nq34bUb9IOvoKBLeNF4D9Avskfe9rtMoEjj6ImXu_i4oIhYS0dx7x1AgHvtAaZFFhq3LBGtR-ZcsSqxNzVg-4PRUI9zcytQkk_YJXndNSfhVdmYmnxkgx1XXisGv1FG5GOmEK4jZ_Ih0riX5icFnHrgniADr4bA2G7TYh4OeGBrYLyFN_BDOvq3nFGrXVWrTLhaYyjxOr4rZqJPKK2ybmMsq466Ke1ZtE-wNQ" -H "Origin: https://www.encoretvb.com" "https://edge.api.brightcove.com/playback/v1/accounts/5324042807001/videos/6005570109001" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r encoreTVB:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'error_subcode' | cut -f4 -d'"')
    if [[ "$result" == "CLIENT_GEO" ]]; then
        echo -n -e "\r encoreTVB:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo $tmpresult | python -m json.tool 2>/dev/null | grep 'account_id' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -n -e "\r encoreTVB:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r encoreTVB:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Molotov() {
    echo -n -e " Molotov:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 "https://fapi.molotov.tv/v1/open-europe/is-france" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Molotov:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    echo $tmpresult | python -m json.tool 2>/dev/null | grep 'false' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -n -e "\r Molotov:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo $tmpresult | python -m json.tool 2>/dev/null | grep 'true' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -n -e "\r Molotov:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Molotov:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Salto() {
    echo -n -e " Salto:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 "https://geo.salto.fr/v1/geoInfo/")
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Salto:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local CountryCode=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'country_code' | cut -f4 -d'"')
    local AllowedCode="FR,GP,MQ,GF,RE,YT,PM,BL,MF,WF,PF,NC"
    echo ${AllowedCode} | grep ${CountryCode} >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -n -e "\r Salto:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Salto:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_LineTV.TW() {
    echo -n -e " LineTV.TW:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://www.linetv.tw/api/part/11829/eps/1/part?chocomemberId=")
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r LineTV.TW:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | awk '{print $2}' | cut -f1 -d',')
    if [ -n "$result" ]; then
        if [ "$result" = "228" ]; then
            echo -n -e "\r LineTV.TW:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        else
            echo -n -e "\r LineTV.TW:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r LineTV.TW:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Viu.com() {
    echo -n -e " Viu.com:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.viu.com/")
    if [ "$tmpresult" = "000" ]; then
        echo -n -e "\r Viu.com:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    result=$(echo $tmpresult | cut -f5 -d"/")
    if [ -n "$result" ]; then
        if [[ "$result" == "no-service" ]]; then
            echo -n -e "\r Viu.com:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        else
            result=$(echo $result | tr [:lower:] [:upper:])
            echo -n -e "\r Viu.com:\t\t\t\t${Font_Green}Yes (Region: ${result})${Font_Suffix}\n"
            return
        fi

    else
        echo -n -e "\r Viu.com:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_Niconico() {
    echo -n -e " Niconico:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sSL --max-time 10 "https://www.nicovideo.jp/watch/so23017073" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Niconico:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    echo $tmpresult | grep '同じ地域' >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
        echo -n -e "\r Niconico:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Niconico:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_ParamountPlus() {
    echo -n -e " Paramount+:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.paramountplus.com/" | grep 'intl')

    if [ -n "$result" ]; then
        echo -n -e "\r Paramount+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Paramount+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Paramount+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_KKTV() {
    echo -n -e " KKTV:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api.kktv.me/v3/ipcheck")
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r KKTV:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'country' | cut -f4 -d'"')
    if [[ "$result" == "TW" ]]; then
        echo -n -e "\r KKTV:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r KKTV:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_PeacockTV() {
    echo -n -e " Peacock TV:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -Ss -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.peacocktv.com/" | grep 'unavailable')
    if [[ "$result" == "curl"* ]]; then
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ -n "$result" ]; then
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Peacock TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Peacock TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_FOD() {
    echo -n -e " FOD(Fuji TV):\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://geocontrol1.stream.ne.jp/fod-geo/check.xml?time=1624504256")
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r FOD(Fuji TV):\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    echo $tmpresult | grep 'true' >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
        echo -n -e "\r FOD(Fuji TV):\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r FOD(Fuji TV):\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_YouTube_Premium() {
    echo -n -e " YouTube Premium:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} --max-time 10 -sSL -H "Accept-Language: en" -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279" "https://www.youtube.com/premium" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isCN=$(echo $tmpresult | grep 'www.google.cn')
    if [ -n "$isCN" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green} (Region: CN)${Font_Suffix} \n"
        return
    fi
    local isNotAvailable=$(echo $tmpresult | grep 'Premium is not available in your country')
    local region=$(echo $tmpresult | grep "countryCode" | sed 's/.*"countryCode"//' | cut -f2 -d'"')
    local isAvailable=$(echo $tmpresult | grep 'manageSubscriptionButton')

    if [ -n "$isNotAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} \n"
        return
    elif [ -n "$isAvailable" ] && [ -n "$region" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    elif [ -z "$region" ] && [ -n "$isAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_YouTube_CDN() {
    echo -n -e " YouTube CDN:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 "https://redirector.googlevideo.com/report_mapping" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube Region:\t\t\t${Font_Red}Check Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local iata=$(echo $tmpresult | grep router | cut -f2 -d'"' | cut -f2 -d"." | sed 's/.\{2\}$//' | tr [:lower:] [:upper:])
    local checkfailed=$(echo $tmpresult | grep "=>")
    if [ -z "$iata" ] && [ -n "$checkfailed" ]; then
        CDN_ISP=$(echo $checkfailed | awk '{print $3}' | cut -f1 -d"-" | tr [:lower:] [:upper:])
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}Associated with [$CDN_ISP]${Font_Suffix}\n"
        return
    elif [ -n "$iata" ]; then
        local lineNo=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt" | cut -f3 -d"|" | sed -n "/${iata}/=")
        local location=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//')
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}$location${Font_Suffix}\n"
        return
    else
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Undetectable${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_BritBox() {
    echo -n -e " BritBox:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.britbox.com/" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r BritBox:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'locationnotsupported')
    if [ -n "$result" ]; then
        echo -n -e "\r BritBox:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r BritBox:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r BritBox:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_PrimeVideo_Region() {
    echo -n -e " Amazon Prime Video:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -sL --max-time 10 "https://www.primevideo.com")

    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep '"currentTerritory":' | sed 's/.*currentTerritory//' | cut -f3 -d'"' | head -n 1)
    if [ -n "$result" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Green}Yes (Region: $result)${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Unsupported${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Radiko() {
    echo -n -e " Radiko:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 "https://radiko.jp/area?_=1625406539531")

    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r Radiko:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local checkfailed=$(echo $tmpresult | grep 'class="OUT"')
    if [ -n "$checkfailed" ]; then
        echo -n -e "\r Radiko:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local checksuccess=$(echo $tmpresult | grep 'JAPAN')
    if [ -n "$checksuccess" ]; then
        area=$(echo $tmpresult | awk '{print $2}' | sed 's/.*>//')
        echo -n -e "\r Radiko:\t\t\t\t${Font_Green}Yes (City: $area)${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Radiko:\t\t\t\t${Font_Red}Unsupported${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_DMM() {
    echo -n -e " DMM:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 "https://api-p.videomarket.jp/v3/api/play/keyauth?playKey=4c9e93baa7ca1fc0b63ccf418275afc2&deviceType=3&bitRate=0&loginFlag=0&connType=" -H "X-Authorization: 2bCf81eLJWOnHuqg6nNaPZJWfnuniPTKz9GXv5IS")

    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r DMM:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local checkfailed=$(echo $tmpresult | grep 'Access is denied')
    if [ -n "$checkfailed" ]; then
        echo -n -e "\r DMM:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local checksuccess=$(echo $tmpresult | grep 'PlayKey has expired')
    if [ -n "$checksuccess" ]; then
        echo -n -e "\r DMM:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r DMM:\t\t\t\t\t${Font_Red}Unsupported${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Catchplay() {
    echo -n -e " CatchPlay+:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://sunapi.catchplay.com/geo" -H "authorization: Basic NTQ3MzM0NDgtYTU3Yi00MjU2LWE4MTEtMzdlYzNkNjJmM2E0Ok90QzR3elJRR2hLQ01sSDc2VEoy")
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r CatchPlay+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'code' | awk '{print $2}' | cut -f2 -d'"')
    if [ -n "$result" ]; then
        if [ "$result" = "0" ]; then
            echo -n -e "\r CatchPlay+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        elif [ "$result" = "100016" ]; then
            echo -n -e "\r CatchPlay+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        else
            echo -n -e "\r CatchPlay+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r CatchPlay+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_HotStar() {
    echo -n -e " HotStar:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api.hotstar.com/o/v1/page/1557?offset=0&size=20&tao=0&tas=20")
    if [ "$result" = "000" ]; then
        echo -n -e "\r HotStar:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "401" ]; then
        local region=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -sI "https://www.hotstar.com" | grep 'geo=' | sed 's/.*geo=//' | cut -f1 -d",")
        local site_region=$(curl $useNIC $xForward -${1} ${ssll} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.hotstar.com" | sed 's@.*com/@@' | tr [:lower:] [:upper:])
        if [ -n "$region" ] && [ "$region" = "$site_region" ]; then
            echo -n -e "\r HotStar:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
            return
        else
            echo -n -e "\r HotStar:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        fi
    elif [ "$result" = "475" ]; then
        echo -n -e "\r HotStar:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HotStar:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_LiTV() {
    echo -n -e " LiTV:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 -X POST "https://www.litv.tv/vod/ajax/getUrl" -d '{"type":"noauth","assetId":"vod44868-010001M001_800K","puid":"6bc49a81-aad2-425c-8124-5b16e9e01337"}' -H "Content-Type: application/json" 2>&1)
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r LiTV:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'errorMessage' | awk '{print $2}' | cut -f1 -d"," | cut -f2 -d'"')
    if [ -n "$result" ]; then
        if [ "$result" = "null" ]; then
            echo -n -e "\r LiTV:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        elif [ "$result" = "vod.error.outsideregionerror" ]; then
            echo -n -e "\r LiTV:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r LiTV:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_FuboTV() {
    echo -n -e " Fubo TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://www.fubo.tv/welcome" | gunzip 2>/dev/null)

    local result=$(echo $tmpresult | grep 'countryCode' | sed 's/.*countryCode//' | cut -f3 -d'"')
    if [ -n "$result" ]; then
        if [[ "$result" == "USA" ]]; then
            echo -n -e "\r Fubo TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        else
            echo -n -e "\r Fubo TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r Fubo TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Fox() {
    echo -n -e " Fox:\t\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://x-live-fox-stgec.uplynk.com/ausw/slices/8d1/d8e6eec26bf544f084bad49a7fa2eac5/8d1de292bcc943a6b886d029e6c0dc87/G00000000.ts?pbs=c61e60ee63ce43359679fb9f65d21564&cloud=aws&si=0")
    if [ "$result" = "000" ]; then
        echo -n -e "\r FOX:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r FOX:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r FOX:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r FOX:\t\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Joyn() {
    echo -n -e " Joyn:\t\t\t\t\t->\c"
    local tmpauth=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 -X POST "https://auth.joyn.de/auth/anonymous" -H "Content-Type: application/json" -d '{"client_id":"b74b9f27-a994-4c45-b7eb-5b81b1c856e7","client_name":"web","anon_device_id":"b74b9f27-a994-4c45-b7eb-5b81b1c856e7"}')
    if [ -z "$tmpauth" ]; then
        echo -n -e "\r Joyn:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    auth=$(echo $tmpauth | python -m json.tool 2>/dev/null | grep access_token | awk '{print $2}' | cut -f2 -d'"')
    local result=$(curl $useNIC $xForward -s "https://api.joyn.de/content/entitlement-token" -H "x-api-key: 36lp1t4wto5uu2i2nk57ywy9on1ns5yg" -H "content-type: application/json" -d '{"content_id":"daserste-de-hd","content_type":"LIVE"}' -H "authorization: Bearer $auth")
    if [ -n "$result" ]; then
        isBlock=$(echo $result | python -m json.tool 2>/dev/null | grep 'code' | awk '{print $2}' | cut -f2 -d'"')
        if [[ "$isBlock" == "ENT_AssetNotAvailableInCountry" ]]; then
            echo -n -e "\r Joyn:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
            return
        else
            echo -n -e "\r Joyn:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        fi
    else
        echo -n -e "\r Joyn:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_SKY_DE() {
    echo -n -e " Sky:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://edge.api.brightcove.com/playback/v1/accounts/1050888051001/videos/6247131490001" -H "Accept: application/json;pk=BCpkADawqM0OXCLe4eIkpyuir8Ssf3kIQAM62a1KMa4-1_vTOWQIxoHHD4-oL-dPmlp-rLoS-WIAcaAMKuZVMR57QY4uLAmP4Ov3V416hHbqr0GNNtzVXamJ6d4-rA3Xi98W-8wtypdEyjGEZNepUCt3D7UdMthbsG-Ean3V4cafT4nZX03st5HlyK1chp51SfA-vKcAOhHZ4_Oa9TTN61tEH6YqML9PWGyKrbuN5myICcGsFzP3R2aOF8c5rPCHT2ZAiG7MoavHx8WMjhfB0QdBr2fphX24CSpUKlcjEnQJnBiA1AdLg9iyReWrAdQylX4Eyhw5OwKiCGJznfgY6BDtbUmeq1I9r9RfmhP5bfxVGjILSEFZgXbMqGOvYdrdare0aW2fTCxeHdHt0vyKOWTC6CS1lrGJF2sFPKn1T1csjVR8s4MODqCBY1PTbHY4A9aZ-2MDJUVJDkOK52hGej6aXE5b9N9_xOT2B9wbXL1B1ZB4JLjeAdBuVtaUOJ44N0aCd8Ns0o02E1APxucQqrjnEociLFNB0Bobe1nkGt3PS74IQcs-eBvWYSpolldMH6TKLu8JqgdnM4WIp3FZtTWJRADgAmvF9tVDUG9pcJoRx_CZ4im-rn-AzN3FeOQrM4rTlU3Q8YhSmyEIoxYYqsFDwbFlhsAcvqQkgaElYtuciCL5i3U8N4W9rIhPhQJzsPafmLdWxBP_FXicyek25GHFdQzCiT8nf1o860Jv2cHQ4xUNcnP-9blIkLy9JmuB2RgUXOHzWsrLGGW6hq9wLUtqwEoxcEAAcNJgmoC0k8HE-Ga-NHXng6EFWnqiOg_mZ_MDd7gmHrrKLkQV" -H "Origin: https://www.sky.de")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Sky:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep error_subcode | cut -f4 -d'"')
    if [[ "$result" == "CLIENT_GEO" ]]; then
        echo -n -e "\r Sky:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$result" ] && [ -n "$tmpresult" ]; then
        echo -n -e "\r Sky:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Sky:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_ZDF() {
    echo -n -e " ZDF: \t\t\t\t\t->\c"
    # 测试，连续请求两次 (单独请求一次可能会返回35, 第二次开始变成0)
    local result=$(curl $useNIC $xForward --user-agent "${UA_Dalvik}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://ssl.zdf.de/geo/de/geo.txt/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r ZDF: \t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "404" ]; then
        echo -n -e "\r ZDF: \t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r ZDF: \t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r ZDF: \t\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_HBOGO_ASIA() {
    echo -n -e " HBO GO Asia:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api2.hbogoasia.com/v1/geog?lang=undefined&version=0&bundleId=www.hbogoasia.com")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r HBO GO Asia:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep territory)
    if [ -z "$result" ]; then
        echo -n -e "\r HBO GO Asia:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -n "$result" ]; then
        local CountryCode=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep country | cut -f4 -d'"')
        echo -n -e "\r HBO GO Asia:\t\t\t\t${Font_Green}Yes (Region: $CountryCode)${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HBO GO Asia:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_HBOGO_EUROPE() {
    echo -n -e " HBO GO Europe:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api.ugw.hbogo.eu/v3.0/GeoCheck/json/HUN")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r HBO GO Europe:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep allow | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "1" ]]; then
        echo -n -e "\r HBO GO Europe:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "0" ]]; then
        echo -n -e "\r HBO GO Europe:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HBO GO Europe:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_EPIX() {
    echo -n -e " Epix:\t\t\t\t\t->\c"
    tmpToken=$(curl $useNIC $xForward -${1} ${ssll} -s -X POST "https://api.epix.com/v2/sessions" -H "Content-Type: application/json" -d '{"device":{"guid":"e2add88e-2d92-4392-9724-326c2336013b","format":"console","os":"web","app_version":"1.0.2","model":"browser","manufacturer":"google"},"apikey":"f07debfcdf0f442bab197b517a5126ec","oauth":{"token":null}}')
    if [ -z "$tmpToken" ]; then
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [[ "$tmpToken" == "error code"* ]]; then
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    EpixToken=$(echo $tmpToken | python -m json.tool 2>/dev/null | grep 'session_token' | cut -f4 -d'"')
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -X POST -s --max-time 10 "https://api.epix.com/v2/movies/16921/play" -d '{}' -H "X-Session-Token: $EpixToken")

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep status | cut -f4 -d'"')
    if [[ "$result" == "PROXY_DETECTED" ]]; then
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "GEO_BLOCKED" ]]; then
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "NOT_SUBSCRIBED" ]]; then
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Epix:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_NLZIET() {
    echo -n -e " NLZIET:\t\t\t\t->\c"
    TmpFallBackCode=$(curl $useNIC $xForward -X GET -${1} ${ssll} -s --max-time 10 "https://id.nlziet.nl/connect/authorize/callback?client_id=triple-web&redirect_uri=https%3A%2F%2Fapp.nlziet.nl%2Fcallback&response_type=code&scope=openid%20api&state=91b508206f154b8381d3cc9061170527&code_challenge=EF_HpSX8a_leJOXmHqsYpBKjNRX0D8oZh_HfremhSWE&code_challenge_method=S256&response_mode=query" -b "optanonStatus=,C0001,; _gid=GA1.2.301664903.1627130663; OptanonConsent=isIABGlobal=false&datestamp=Sat+Jul+24+2021+20%3A44%3A23+GMT%2B0800+(%E9%A6%99%E6%B8%AF%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4)&version=6.17.0&hosts=&landingPath=https%3A%2F%2Fapp.nlziet.nl%2F&groups=C0001%3A1%2CC0002%3A0%2CC0003%3A0%2CC0004%3A0; _ga=GA1.2.1715247671.1627130661; _ga_LQL66TVRW1=GS1.1.1627130674.1.1.1627130679.0; _ga_QVB71SF0T8=GS1.1.1627130674.1.1.1627130679.0; .AspNetCore.Antiforgery.iEdXBvgZzA4=CfDJ8IdkGvI8o6RKkusMbm16dgZLQ3gjhTBrGZ5YAf7IYcvZ_uyXtvFmF8n87s9O1A6_hGU2cylV3fP7KrNnOndoMYFzeQTtFjYYe6rKr7G7tnvK5nDlZ1voXmUWbOynzDibE8HvkIICFkMzAZQksRtufiA; _ga_YV1B2GE80N=GS1.1.1627130661.1.1.1627130679.0; idsrv.session=3AF23B3FB60D818D8D6B519258D305C4; idsrv=CfDJ8IdkGvI8o6RKkusMbm16dgY4Sqm-8MQ1fT9qsFj38GA2PTr53t9IZNOTNbfRBqf4_2ymzxFOJr3WeVh_xbqM-yiQtvZ3LKdkZW8jR8g6jE9WeZj5kxdUZYSYRsOkUc-ZCQJA59txaiunIwwgwPfbRYW86mL_ZL_cTVZZldVNHswXPKvDKeeD9ieyXVGvLFEjgEUsNXzukaPN6SFuC0UISPcU8rqU9DdLp0y5QeoqE_z_nTlVgB65F-bGYeKtFVtk1uf7TYDgxnFeTJt5NpigsRk2zcIi0bmrzkgKd7oUQrAfVkUoy8T1-SnHAjN0VpDn4fRE4t1LdsU89IbV99pMVN2hvx5UrNT09lsSllkqzJXYoxC2dLQihWWcfH5J0lUn9GjFPTZWFOSw_6i164eYY2cpfvROcr3MJH0dXPf1kgLXNjN5ejjjCEPmgeMGvFdYS4cusx0tgvDp5R2hpbZGpRXneTgwAjFs9vgYuf_-r7cdb-fdSy-oohsdEDIIz5Zz_-7TvOl3hHEShAYaHjyUYWcm90E-6N3mjm7sBXUe9cDqbqbfpwgr1ciW0GbuZCqXaShrFvjE48EXnwt46TuBDAJJtVm4OZPE8ngJYscQrel7AJvm8tPpv10P6vw_Hva5IvCPxcLkyFj4xnbmY6hBU3-WQNawtZ67098QTEvMKgF44_QI0x5xP8NZ8HR2GDabLtMh88enklIB8_j7dp3RwoSLn9N61gZJWhBj9mU5FioAOGKsNJD4iWtPXKwUU0Yz4XnjD1KYL88BE3j7-Z5qiLQQGWj5GkKk7PLhPMA_PghLjE6KKKoWTny6NSXXyPSGZIHwlV2NGTH8EQmKoBq_xfejG-oBqSP0aCAf2apl6bwDHrBK3YVigLWPlej_4OKj7BC-KXhHxW7bNY4vHQ5EUHw" -I | grep Location | sed 's/.*callback?code=//' | cut -f1 -d"&")
    local tmpauth=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 -X POST "https://id.nlziet.nl/connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=triple-web&code=${TmpFallBackCode}&redirect_uri=https%3A%2F%2Fapp.nlziet.nl%2Fcallback&code_verifier=04850de4083d48adb0bf6db3ebfd038fe27a7881de914b95a18d90ceb350316ed05a0e39e72440e6ace015ddc11d28b5&grant_type=authorization_code")

    if [ -z "$tmpauth" ]; then
        echo -n -e "\r NLZIET:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

    local auth=$(echo $tmpauth | python -m json.tool 2>/dev/null | grep access_token | awk '{print $2}' | cut -f2 -d'"')
    local result=$(curl $useNIC $xForward -X GET -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api.nlziet.nl/v7/stream/handshake/Widevine/Dash/VOD/rJDaXnOP4kaRXnZdR_JofA?playerName=BitmovinWeb" -H "authorization: Bearer $auth")

    if [ "$result" = "000" ]; then
        echo -n -e "\r NLZIET:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    elif [ "$result" = "500" ]; then
        echo -n -e "\r NLZIET:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r NLZIET:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r NLZIET:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_videoland() {
    echo -n -e " videoland:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://www.videoland.com/api/v3/geo")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r videoland:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep has_access | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r videoland:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r videoland:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r videoland:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_NPO_Start_Plus() {
    echo -n -e " NPO Start Plus:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://start-player.npo.nl/video/KN_1726624/streams?profile=dash-widevine&quality=npo&tokenId=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzbWFydHRhZyI6eyJzaXRlSWQiOiI0In0sImhhc1N1YnNjcmlwdGlvbiI6IiIsImhhc1ByZW1pdW1TdWJzY3JpcHRpb24iOiIiLCJlbGVtZW50SWQiOiJwbGF5ZXItS05fMTcyNjYyNCIsIm1lZGlhSWQiOiJLTl8xNzI2NjI0IiwidG9wc3BpbiI6eyJwYXJ0eUlkIjoiIiwicHJvZmlsZUlkIjoiIn0sImhhc1NldHRpbmdzIjoiMSIsImhhc0FkQ29uc2VudCI6IjAiLCJzaGFyZSI6IjAiLCJlbmFibGVUaHVtYm5haWxTY3JvbGwiOiIxIiwibWFya2VycyI6IjEiLCJyZWNvbW1lbmRhdGlvbnMiOiIyNSIsImVuZHNjcmVlbiI6eyJoaWRlX2Zvcl90eXBlcyI6WyJmcmFnbWVudCIsImNsaXAiLCJ0cmFpbGVyIl19LCJzdHlsZVZlcnNpb24iOiIyIiwibW9yZUJ1dHRvbiI6IjEiLCJlbmRPZkNvbnRlbnRUZXh0IjoiMSIsImNocm9tZWNhc3QiOnsiZW5hYmxlZCI6IjEifSwic3R5bGluZyI6eyJ0aXRsZSI6eyJkaXNwbGF5Ijoibm9uZSJ9fSwiYXV0b3BsYXkiOiIwIiwicGFnZVVybCI6Imh0dHA6XC9cL3d3dy5ucG9zdGFydC5ubFwvc3dhbmVuYnVyZ1wvMTktMDctMjAyMVwvS05fMTcyNjYyNCIsInN0ZXJSZWZlcnJhbFVybCI6Imh0dHA6XC9cL3d3dy5ucG9zdGFydC5ubFwvc3dhbmVuYnVyZ1wvMTktMDctMjAyMVwvS05fMTcyNjYyNCIsInN0ZXJTaXRlSWQiOiJucG9zdGFydCIsInN0eWxlc2hlZXQiOiJodHRwczpcL1wvd3d3Lm5wb3N0YXJ0Lm5sXC9zdHlsZXNcL3BsYXllci5jc3MiLCJjb252aXZhIjp7ImVuYWJsZWQiOiIxIiwiYnJvYWRjYXN0ZXJOYW1lIjoiTlBPU1RBUlQifSwiaWF0IjoxNjI3MTM2MTEzLCJuYmYiOjE2MjcxMzYxMTMsImV4cCI6MTYyNzE2NDkxMywiY29uc3VtZXJJZCI6bnVsbCwiaXNQbGF5bGlzdCI6ZmFsc2UsInJlZmVycmVyVXJsIjpudWxsLCJza2lwQ2F0YWxvZyI6MCwibm9BZHMiOjAsImlzcyI6ImV5SnBkaUk2SWpkdldrUjFSbFJRWVcwclREVkZjVWRxWVhOY0x6RkJQVDBpTENKMllXeDFaU0k2SW5KelkwcGFUbVpwWTNoV2MyMXphMXBRU0VOeGVEVkJXamN4YXl0UFZraHJOblJQTTBwM2JsZERabFpxSzBneFRtdzJhV3c1UW1SaGJFcDFWV2hvYUZZaUxDSnRZV01pT2lKbU1EUXdNRE5sTlRGbVlUSmpPR05tTTJVMFpEYzBaREF3TURObU9EaGxNelZoWTJNelltSXhaalJtWTJaa05UUTJZVFF6TURNNE9USTJNVFUzWlRsaUluMD0ifQ.aMQGym3tnPu9JM6Mb8XWCm46cB980Sk-ZGvRX0V2gV8&streamType=broadcast&isYospace=0&videoAgeRating=12&isChromecast=0&mobile=0&ios=0")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r NPO Start Plus:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isGeoBlocked=$(echo $tmpresult | sed 's/.*"error":"//' | grep 'Dit programma mag niet bekeken worden vanaf jouw locatie')
    local isError=$(echo $tmpresult | grep erro)
    if [ -z "$isGeoBlocked" ]; then
        echo -n -e "\r NPO Start Plus:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$isError" ]; then
        echo -n -e "\r NPO Start Plus:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    else
        echo -n -e "\r NPO Start Plus:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_RakutenTV() {
    echo -n -e " Rakuten TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://rakuten.tv" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Rakuten TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'waitforit')
    if [ -n "$result" ]; then
        echo -n -e "\r Rakuten TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Rakuten TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Rakuten TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_HBO_Spain() {
    echo -n -e " HBO Spain:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api-discovery.hbo.eu/v1/discover/hbo?language=null&product=hboe" -H "X-Client-Name: web")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r HBO Spain:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep signupAllowed | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r HBO Spain:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r HBO Spain:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HBO Spain:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_PANTAYA() {
    echo -n -e " PANTAYA:\t\t\t\t->\c"
    local authorization=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 "https://www.pantaya.com/sapi/header/v1/pantaya/us/735a16260c2b450686e68532ccd7f742" -H "Referer: https://www.pantaya.com/es/")
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://auth.pantaya.com/api/v4/User/geolocation" -H "AuthTokenAuthorization: $authorization")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r PANTAYA:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isAllowedAccess=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isAllowedAccess | awk '{print $2}' | cut -f1 -d",")
    local isAllowedCountry=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isAllowedCountry | awk '{print $2}' | cut -f1 -d",")
    local isKnownProxy=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isKnownProxy | awk '{print $2}' | cut -f1 -d",")
    if [[ "$isAllowedAccess" == "true" ]] && [[ "$isAllowedCountry" == "true" ]] && [[ "$isKnownProxy" == "false" ]]; then
        echo -n -e "\r PANTAYA:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$isAllowedAccess" == "false" ]]; then
        echo -n -e "\r PANTAYA:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$isKnownProxy" == "false" ]]; then
        echo -n -e "\r PANTAYA:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r PANTAYA:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_Starz() {
    echo -n -e " Starz:\t\t\t\t\t->\c"
    local authorization=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 "https://www.starz.com/sapi/header/v1/starz/us/09b397fc9eb64d5080687fc8a218775b" -H "Referer: https://www.starz.com/us/en/")
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://auth.starz.com/api/v4/User/geolocation" -H "AuthTokenAuthorization: $authorization")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Starz:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isAllowedAccess=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isAllowedAccess | awk '{print $2}' | cut -f1 -d",")
    local isAllowedCountry=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isAllowedCountry | awk '{print $2}' | cut -f1 -d",")
    local isKnownProxy=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isKnownProxy | awk '{print $2}' | cut -f1 -d",")
    if [[ "$isAllowedAccess" == "true" ]] && [[ "$isAllowedCountry" == "true" ]] && [[ "$isKnownProxy" == "false" ]]; then
        echo -n -e "\r Starz:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$isAllowedAccess" == "false" ]]; then
        echo -n -e "\r Starz:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$isKnownProxy" == "false" ]]; then
        echo -n -e "\r Starz:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Starz:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_CanalPlus() {
    echo -n -e " Canal+:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://boutique-tunnel.canalplus.com/" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Canal+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'othercountry')
    if [ -n "$result" ]; then
        echo -n -e "\r Canal+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Canal+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Canal+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_CBCGem() {
    echo -n -e " CBC Gem:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://www.cbc.ca/g/stats/js/cbc-stats-top.js")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r CBC Gem:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | sed 's/.*country":"//' | cut -f1 -d"}" | cut -f1 -d'"')
    if [[ "$result" == "CA" ]]; then
        echo -n -e "\r CBC Gem:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r CBC Gem:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_AcornTV() {
    echo -n -e " Acorn TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s -L --max-time 10 "https://acorn.tv/")
    local isblocked=$(curl $useNIC $xForward -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://acorn.tv/")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Acorn TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [[ "$isblocked" == "403" ]]; then
        echo -n -e "\r Acorn TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep 'Not yet available in your country')
    if [ -n "$result" ]; then
        echo -n -e "\r Acorn TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Acorn TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Crave() {
    echo -n -e " Crave:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://capi.9c9media.com/destinations/se_atexace/platforms/desktop/bond/contents/2205173/contentpackages/4279732/manifest.mpd")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Crave:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'Geo Constraint Restrictions')
    if [ -n "$result" ]; then
        echo -n -e "\r Crave:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Crave:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Amediateka() {
    echo -n -e " Amediateka:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://www.amediateka.ru/")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Amediateka:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'VPN')
    if [ -n "$result" ]; then
        echo -n -e "\r Amediateka:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Amediateka:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_MegogoTV() {
    echo -n -e " Megogo TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://ctx.playfamily.ru/screenapi/v4/preparepurchase/web/1?elementId=0b974dc3-d4c5-4291-9df5-81a8132f67c5&elementAlias=51459024&elementType=GAME&withUpgradeSubscriptionReturnAmount=true&forceSvod=true&includeProductsForUpsale=false&sid=mDRnXOffdh_l2sBCyUIlbA" -H "X-SCRAPI-CLIENT-TS: 1627391624026")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Megogo TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep status | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "0" ]]; then
        echo -n -e "\r Megogo TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "502" ]]; then
        echo -n -e "\r Megogo TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Megogo TV:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_RaiPlay() {
    echo -n -e " Rai Play:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://mediapolisvod.rai.it/relinker/relinkerServlet.htm?cont=VxXwi7UcqjApssSlashbjsAghviAeeqqEEqualeeqqEEqual&output=64")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Rai Play:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'no_available')
    if [ -n "$result" ]; then
        echo -n -e "\r Rai Play:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Rai Play:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_TVBAnywhere() {
    echo -n -e " TVBAnywhere+:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://uapisfm.tvbanywhere.com.sg/geoip/check/platform/android")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'allow_in_this_country' | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_ProjectSekai() {
    echo -n -e " Project Sekai: Colorful Stage:\t\t->\c"
    local result=$(curl $useNIC $xForward --user-agent "User-Agent: pjsekai/48 CFNetwork/1240.0.4 Darwin/20.6.0" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://game-version.sekai.colorfulpalette.org/1.8.1/3ed70b6a-8352-4532-b819-108837926ff5")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Project Sekai: Colorful Stage:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Project Sekai: Colorful Stage:\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Project Sekai: Colorful Stage:\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Project Sekai: Colorful Stage:\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_KonosubaFD() {
    echo -n -e " Konosuba Fantastic Days:\t\t->\c"
    local result=$(curl $useNIC $xForward -X POST --user-agent "User-Agent: pj0007/212 CFNetwork/1240.0.4 Darwin/20.6.0" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api.konosubafd.jp/api/masterlist")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Konosuba Fantastic Days:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Konosuba Fantastic Days:\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Konosuba Fantastic Days:\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Konosuba Fantastic Days:\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_SHOWTIME() {
    echo -n -e " SHOWTIME:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://www.showtime.com/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r SHOWTIME:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r SHOWTIME:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r SHOWTIME:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r SHOWTIME:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_NBATV() {
    echo -n -e " NBA TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sSL --max-time 10 "https://www.nba.com/watch/" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r NBA TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | grep 'Service is not available in your region')
    if [ -n "$result" ]; then
        echo -n -e "\r NBA TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r NBA TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_ATTNOW() {
    echo -n -e " Directv Stream:\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://www.atttvnow.com/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Directv Stream:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Directv Stream:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Directv Stream:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_CineMax() {
    echo -n -e " CineMax Go:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://play.maxgo.com/")
    if [ "$result" = "000" ]; then
        echo -n -e "\r CineMax Go:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r CineMax Go:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r CineMax Go:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_NetflixCDN() {
    echo -n -e " Netflix Preferred CDN:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    elif [ -n "$(echo $tmpresult | grep '>403<')" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (IP Banned By Netflix)${Font_Suffix}\n"
        return
    fi

    local CDNAddr=$(echo $tmpresult | sed 's/.*"url":"//' | cut -f3 -d"/")
    if [[ "$1" == "6" ]]; then
        nslookup -q=AAAA $CDNAddr >~/v6_addr.txt
        ifAAAA=$(cat ~/v6_addr.txt | grep 'AAAA address' | awk '{print $NF}')
        if [ -z "$ifAAAA" ]; then
            CDNIP=$(cat ~/v6_addr.txt | grep Address | sed -n '$p' | awk '{print $NF}')
        else
            CDNIP=${ifAAAA}
        fi
    else
        CDNIP=$(nslookup $CDNAddr | sed '/^\s*$/d' | awk 'END {print}' | awk '{print $2}')
    fi

    if [ -z "$CDNIP" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (CDN IP Not Found)${Font_Suffix}\n"
        rm -rf ~/v6_addr.txt
        return
    fi

    local CDN_ISP=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -s --max-time 20 "https://api.ip.sb/geoip/$CDNIP" | python -m json.tool 2>/dev/null | grep 'isp' | cut -f4 -d'"')
    local iata=$(echo $CDNAddr | cut -f3 -d"-" | sed 's/.\{3\}$//' | tr [:lower:] [:upper:])
    local isIataFound1=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt" | grep $iata)
    local isIataFound2=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode2.txt" | grep $iata)

    if [ -n "$isIataFound1" ]; then
        local lineNo=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt" | cut -f3 -d"|" | sed -n "/${iata}/=")
        local location=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//')
    elif [ -z "$isIataFound1" ] && [ -n "$isIataFound2" ]; then
        local lineNo=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode2.txt" | awk '{print $1}' | sed -n "/${iata}/=")
        local location=$(curl $useNIC $xForward -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode2.txt" | awk "NR==${lineNo}" | cut -f2 -d"," | sed -e 's/^[[:space:]]*//' | tr [:upper:] [:lower:] | sed 's/\b[a-z]/\U&/g')
    fi

    if [ -n "$location" ] && [[ "$CDN_ISP" == "Netflix Streaming Services" ]]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Green}$location ${Font_Suffix}\n"
        rm -rf ~/v6_addr.txt
        return
    elif [ -n "$location" ] && [[ "$CDN_ISP" != "Netflix Streaming Services" ]]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Yellow}Associated with [$CDN_ISP] in [$location]${Font_Suffix}\n"
        rm -rf ~/v6_addr.txt
        return
    elif [ -n "$location" ] && [ -z "$CDN_ISP" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}No ISP Info Founded${Font_Suffix}\n"
        rm -rf ~/v6_addr.txt
        return
    fi
}

function MediaUnlockTest_HBO_Nordic() {
    echo -n -e " HBO Nordic:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api-discovery.hbo.eu/v1/discover/hbo?language=null&product=hbon" -H "X-Client-Name: web")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r HBO Nordic:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep signupAllowed | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r HBO Nordic:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r HBO Nordic:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HBO Nordic:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_HBO_Portugal() {
    echo -n -e " HBO Portugal:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://api.ugw.hbogo.eu/v3.0/GeoCheck/json/PRT")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r HBO Portugal:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep allow | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "1" ]]; then
        echo -n -e "\r HBO Portugal:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "0" ]]; then
        echo -n -e "\r HBO Portugal:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r HBO Portugal:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_SkyGo() {
    echo -n -e " Sky Go:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sL --max-time 10 "https://skyid.sky.com/authorise/skygo?response_type=token&client_id=sky&appearance=compact&redirect_uri=skygo://auth")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Sky Go:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep "You don't have permission to access")
    if [ -z "$result" ]; then
        echo -n -e "\r Sky Go:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Sky Go:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_ElevenSportsTW() {
    echo -n -e " Eleven Sports TW:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -s --max-time 10 "https://apis.v-saas.com:9501/member/api/viewAuthorization?contentId=1&memberId=384030&menuId=3&platform=5&imei=c959b475-f846-4a86-8e9b-508048372508")
    local qq=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep '"qq"' | cut -f4 -d'"')
    local st=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep '"st"' | cut -f4 -d'"')
    local m3u_RUL=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep boostStreamUrl | cut -f4 -d'"')
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "${m3u_RUL}?st=${st}&qq=${qq}")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Eleven Sports TW:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Eleven Sports TW:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Eleven Sports TW:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Eleven Sports TW:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_StarPlus() {
    echo -n -e " Star+:\t\t\t\t\t->\c"
    local starcontent=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '10p')
    local tmpresult=$(curl $useNIC $xForward -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://star.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: c3RhciZicm93c2VyJjEuMC4w.COknIGCR7I6N0M5PGnlcdbESHGkNv7POwhFNL-_vIdg" -d "$starcontent" 2>&1)
    local previewcheck=$(curl $useNIC $xForward -${1} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.starplus.com/login")
    local isUnavailable=$(echo $previewcheck | grep unavailable)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Star+:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [ -n "$region" ] && [ -z "$isUnavailable" ] && [[ "$inSupportedLocation" == "false" ]]; then
        echo -n -e "\r Star+:\t\t\t\t\t${Font_Yellow}CDN Relay Available${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [ -n "$isUnavailable" ]; then
        echo -n -e "\r Star+:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r Star+:\t\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    elif [ -z "$region" ]; then
        echo -n -e "\r Star+:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_DirecTVGO() {
    echo -n -e " DirecTV Go:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -Ss -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.directvgo.com/registrarse" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r DirecTV Go:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local isForbidden=$(echo $tmpresult | grep 'proximamente')
    local region=$(echo $tmpresult | cut -f4 -d"/" | tr [:lower:] [:upper:])
    if [ -n "$isForbidden" ]; then
        echo -n -e "\r DirecTV Go:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$isForbidden" ] && [ -n "$region" ]; then
        echo -n -e "\r DirecTV Go:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r DirecTV Go:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_DAM() {
    echo -n -e " Karaoke@DAM:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward --user-agent "${UA_Browser}" -${1} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "http://cds1.clubdam.com/vhls-cds1/site/xbox/sample_1.mp4.m3u8")
    if [[ "$result" == "000" ]]; then
        echo -n -e "\r Karaoke@DAM:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Karaoke@DAM:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Karaoke@DAM:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Karaoke@DAM:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_DiscoveryPlus() {
    echo -n -e " Discovery+:\t\t\t\t->\c"
    local GetToken=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://us1-prod-direct.discoveryplus.com/token?deviceId=d1a4a5d25212400d1e6985984604d740&realm=go&shortlived=true" 2>&1)
    if [[ "$GetToken" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Discovery+:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$GetToken" == "curl"* ]]; then
        echo -n -e "\r Discovery+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local Token=$(echo $GetToken | python -m json.tool 2>/dev/null | grep '"token":' | cut -f4 -d'"')
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://us1-prod-direct.discoveryplus.com/users/me" -b "_gcl_au=1.1.858579665.1632206782; _rdt_uuid=1632206782474.6a9ad4f2-8ef7-4a49-9d60-e071bce45e88; _scid=d154b864-8b7e-4f46-90e0-8b56cff67d05; _pin_unauth=dWlkPU1qWTRNR1ZoTlRBdE1tSXdNaTAwTW1Nd0xUbGxORFV0WWpZMU0yVXdPV1l6WldFeQ; _sctr=1|1632153600000; aam_fw=aam%3D9354365%3Baam%3D9040990; aam_uuid=24382050115125439381416006538140778858; st=${Token}; gi_ls=0; _uetvid=a25161a01aa711ec92d47775379d5e4d; AMCV_BC501253513148ED0A490D45%40AdobeOrg=-1124106680%7CMCIDTS%7C18894%7CMCMID%7C24223296309793747161435877577673078228%7CMCAAMLH-1633011393%7C9%7CMCAAMB-1633011393%7CRKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y%7CMCOPTOUT-1632413793s%7CNONE%7CvVersion%7C5.2.0; ass=19ef15da-95d6-4b1d-8fa2-e9e099c9cc38.1632408400.1632406594" 2>&1)
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep currentLocationTerritory | cut -f4 -d'"')
    if [[ "$result" == "us" ]]; then
        echo -n -e "\r Discovery+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Discovery+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Discovery+:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_ESPNPlus() {
    echo -n -e " ESPN+:${Font_SkyBlue}[Sponsored by Jam]${Font_Suffix}\t\t->\c"
    local espncookie=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '11p')
    local TokenContent=$(curl -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://espn.api.edge.bamgrid.com/token" -H "authorization: Bearer ZXNwbiZicm93c2VyJjEuMC4w.ptUt7QxsteaRruuPmGZFaJByOoqKvDP2a5YkInHrc7c" -d "$espncookie")
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        echo -n -e "\r ESPN+:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    local fakecontent=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '10p')
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local espncontent=$(echo $fakecontent | sed "s/ILOVESTAR/${refreshToken}/g")
    local tmpresult=$(curl -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://espn.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZXNwbiZicm93c2VyJjEuMC4w.ptUt7QxsteaRruuPmGZFaJByOoqKvDP2a5YkInHrc7c" -d "$espncontent" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r ESPN+:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "US" ]] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r ESPN+:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r ESPN+:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Stan() {
    echo -n -e " Stan:\t\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -X POST -sS --max-time 10 "https://api.stan.com.au/login/v1/sessions/web/account")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Stan:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep VPNDetected)
    if [ -z "$result" ]; then
        echo -n -e "\r Stan:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Stan:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_Binge() {
    echo -n -e " Binge:\t\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://auth.streamotion.com.au")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Binge:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Binge:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Binge:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Binge:\t\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Docplay() {
    echo -n -e " Docplay:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -Ss -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.docplay.com/subscribe" | grep 'geoblocked')
    if [[ "$result" == "curl"* ]]; then
        echo -n -e "\r Docplay:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        isKayoSportsOK=2
        return
    elif [ -n "$result" ]; then
        echo -n -e "\r Docplay:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        isKayoSportsOK=0
        return
    else
        echo -n -e "\r Docplay:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        isKayoSportsOK=1
        return
    fi

    echo -n -e "\r Docplay:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    isKayoSportsOK=2
    return

}

function MediaUnlockTest_OptusSports() {
    echo -n -e " Optus Sports:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://sport.optus.com.au/api/userauth/validate/web/username/restriction.check@gmail.com")
    if [ "$result" = "000" ]; then
        echo -n -e "\r Optus Sports:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Optus Sports:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Optus Sports:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Optus Sports:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_KayoSports() {
    echo -n -e " Kayo Sports:\t\t\t\t->\c"
    if [[ "$isKayoSportsOK" = "2" ]]; then
        echo -n -e "\r Kayo Sports:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    elif [[ "$isKayoSportsOK" = "1" ]]; then
        echo -n -e "\r Kayo Sports:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$isKayoSportsOK" = "0" ]]; then
        echo -n -e "\r Kayo Sports:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Kayo Sports:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_NeonTV() {
    echo -n -e " Neon TV:\t\t\t\t->\c"
    local NeonHeader=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '12p')
    local NeonContent=$(curl -s --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies" | sed -n '13p')
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS -X POST "https://api.neontv.co.nz/api/client/gql?" -H "content-type: application/json" -H "$NeonHeader" -d "$NeonContent")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Neon TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep 'RESTRICTED_GEOLOCATION')
    if [ -z "$result" ]; then
        echo -n -e "\r Neon TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Neon TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_SkyGONZ() {
    echo -n -e " SkyGo NZ:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://login.sky.co.nz/authorize?audience=https%3A%2F%2Fapi.sky.co.nz&client_id=dXhXjmK9G90mOX3B02R1kV7gsC4bp8yx&redirect_uri=https%3A%2F%2Fwww.skygo.co.nz&connection=Sky-Internal-Connection&scope=openid%20profile%20email%20offline_access&response_type=code&response_mode=query&state=OXg3QjBGTHpoczVvdG1fRnJFZXVoNDlPc01vNzZjWjZsT3VES2VhN1dDWA%3D%3D&nonce=OEdvci4xZHBHU3VLb1M0T1JRbTZ6WDZJVGQ3R3J0TTdpTndvWjNMZDM5ZA%3D%3D&code_challenge=My5fiXIl-cX79KOUe1yDFzA6o2EOGpJeb6w1_qeNkpI&code_challenge_method=S256&auth0Client=eyJuYW1lIjoiYXV0aDAtcmVhY3QiLCJ2ZXJzaW9uIjoiMS4zLjAifQ%3D%3D")
    if [ "$result" = "000" ]; then
        echo -n -e "\r SkyGo NZ:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r SkyGo NZ:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r SkyGo NZ:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r SkyGo NZ:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_ThreeNow() {
    echo -n -e " ThreeNow:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://bravo-livestream.fullscreen.nz/index.m3u8")
    if [ "$result" = "000" ]; then
        echo -n -e "\r ThreeNow:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "200" ]; then
        echo -n -e "\r ThreeNow:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r ThreeNow:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r ThreeNow:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_MaoriTV() {
    echo -n -e " Maori TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://edge.api.brightcove.com/playback/v1/accounts/1614493167001/videos/6275380737001" -H "Accept: application/json;pk=BCpkADawqM2E9yW4lLgKIEIV5majz5djzZCIqJiYMkP5yYaYdF6AQYq4isPId1ZLtQdGnK1ErLYG0-r1N-3DzAEdbfvw9SFdDWz_i09pLp8Njx1ybslyIXid-X_Dx31b7-PLdQhJCws-vk6Y" -H "Origin: https://www.maoritelevision.com")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Maori TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep error_subcode | cut -f4 -d'"')
    if [[ "$result" == "CLIENT_GEO" ]]; then
        echo -n -e "\r Maori TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$result" ] && [ -n "$tmpresult" ]; then
        echo -n -e "\r Maori TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Maori TV:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_SBSonDemand() {
    echo -n -e " SBS on Demand:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://www.sbs.com.au/api/v3/network?context=odwebsite" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r SBS on Demand:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep country_code | cut -f4 -d'"')
    if [[ "$result" == "AU" ]]; then
        echo -n -e "\r SBS on Demand:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r SBS on Demand:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r SBS on Demand:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_ABCiView() {
    echo -n -e " ABC iView:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS --max-time 10 "https://api.iview.abc.net.au/v2/show/abc-kids-live-stream/video/LS1604H001S00?embed=highlightVideo,selectedSeries")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r ABC iView:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep 'unavailable outside Australia')
    if [ -z "$result" ]; then
        echo -n -e "\r ABC iView:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r ABC iView:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi

}

function MediaUnlockTest_Channel9() {
    echo -n -e " Channel 9:\t\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -Ss -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://login.nine.com.au" | grep 'geoblock')
    if [[ "$result" == "curl"* ]]; then
        echo -n -e "\r Channel 9:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ -n "$result" ]; then
        echo -n -e "\r Channel 9:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Channel 9:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Channel 9:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Telasa() {
    echo -n -e " Telasa:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://api-videopass-anon.kddi-video.com/v1/playback/system_status" -H "X-Device-ID: d36f8e6b-e344-4f5e-9a55-90aeb3403799" 2>&1)
    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Telasa:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local isForbidden=$(echo $tmpresult | grep IPLocationNotAllowed)
    local isAllowed=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep '"type"' | cut -f4 -d'"')
    if [ -n "$isForbidden" ]; then
        echo -n -e "\r Telasa:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -z "$isForbidden" ] && [[ "$isAllowed" == "OK" ]]; then
        echo -n -e "\r Telasa:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Telasa:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_SetantaSports() {
    echo -n -e " Setanta Sports:\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://dce-frontoffice.imggaming.com/api/v2/consent-prompt" -H "Realm: dce.adjara" -H "x-api-key: 857a1e5d-e35e-4fdf-805b-a87b6f8364bf" 2>&1)
    if [[ "$tmpresult" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Setanta Sports:\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Setanta Sports:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep outsideAllowedTerritories | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r Setanta Sports:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r Setanta Sports:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Setanta Sports:\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_MolaTV() {
    echo -n -e " Mola TV:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://mola.tv/api/v2/videos/geoguard/check/vd30491025" 2>&1)
    if [[ "$tmpresult" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Mola TV:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Mola TV:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep isAllowed | awk '{print $2}')
    if [[ "$result" == "true" ]]; then
        echo -n -e "\r Mola TV:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [[ "$result" == "false" ]]; then
        echo -n -e "\r Mola TV:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Mola TV:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_BeinConnect() {
    echo -n -e " Bein Sports Connect:\t\t\t->\c"
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://proxies.bein-mena-production.eu-west-2.tuc.red/proxy/availableOffers")
    if [ "$result" = "000" ] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Bein Sports Connect:\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [ "$result" = "000" ]; then
        echo -n -e "\r Bein Sports Connect:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "500" ]; then
        echo -n -e "\r Bein Sports Connect:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    elif [ "$result" = "451" ]; then
        echo -n -e "\r Bein Sports Connect:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Bein Sports Connect:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_EurosportRO() {
    echo -n -e " Eurosport RO:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://eu3-prod-direct.eurosport.ro/playback/v2/videoPlaybackInfo/sourceSystemId/eurosport-vid1560178?usePreAuth=true" -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJVU0VSSUQ6ZXVyb3Nwb3J0OjlkMWU3MmYyLTdkYjItNDE2Yy1iNmIyLTAwZjQyMWRiN2M4NiIsImp0aSI6InRva2VuLTc0MDU0ZDE3LWFhNWUtNGI0ZS04MDM4LTM3NTE4YjBiMzE4OCIsImFub255bW91cyI6dHJ1ZSwiaWF0IjoxNjM0NjM0MzY0fQ.T7X_JOyvAr3-spU_6wh07re4W-fmbCxZdGaUSZiu1mw' 2>&1)
    if [[ "$tmpresult" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Eurosport RO:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Eurosport RO:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep access.denied.geoblocked)
    if [ -n "$result" ]; then
        echo -n -e "\r Eurosport RO:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Eurosport RO:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Eurosport RO:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_DiscoveryPlusUK() {
    echo -n -e " Discovery+ UK:\t\t\t\t->\c"
    local GetToken=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://disco-api.discoveryplus.co.uk/token?realm=questuk&deviceId=61ee588b07c4df08c02861ecc1366a592c4ad02d08e8228ecfee67501d98bf47&shortlived=true" 2>&1)
    if [[ "$GetToken" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Discovery+ UK:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$GetToken" == "curl"* ]]; then
        echo -n -e "\r Discovery+ UK:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local Token=$(echo $GetToken | python -m json.tool 2>/dev/null | grep '"token":' | cut -f4 -d'"')
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sS "https://disco-api.discoveryplus.co.uk/users/me" -b "st=${Token}" 2>&1)
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep currentLocationTerritory | cut -f4 -d'"')
    if [[ "$result" == "gb" ]]; then
        echo -n -e "\r Discovery+ UK:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Discovery+ UK:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Discovery+ UK:\t\t\t\t${Font_Red}Failed ${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Channel5() {
    echo -n -e " Channel 5:\t\t\t\t->\c"
    local Timestamp=$(date +%s)
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sL --max-time 10 "https://cassie.channel5.com/api/v2/live_media/my5desktopng/C5.json?timestamp=${Timestamp}&auth=0_rZDiY0hp_TNcDyk2uD-Kl40HqDbXs7hOawxyqPnbI" 2>&1)
    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep code | cut -f4 -d'"')
    if [ -z "$result" ] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Channel 5:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
    elif [[ "$result" == "4003" ]]; then
        echo -n -e "\r Channel 5:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ -n "$result" ] && [[ "$result" != "4003" ]]; then
        echo -n -e "\r Channel 5:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Channel 5:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_MyVideo() {
    echo -n -e " MyVideo:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://www.myvideo.net.tw/login.do" 2>&1)
    if [[ "$tmpresult" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r MyVideo:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
    elif [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r MyVideo:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | grep 'serviceAreaBlock')
    if [ -n "$result" ]; then
        echo -n -e "\r MyVideo:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    else
        echo -n -e "\r MyVideo:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r MyVideo:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Channel7() {
    echo -n -e " Channel 7:\t\t\t\t->\c"
    local GetPlayURL=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 "https://csm-e-cen7uswxaws102j8-3stdkepcx398.tls1.yospace.com/csm/extlive/sevenprd01,SYD1.m3u8?appId=7plus&deviceType=web&platformType=web&ppId=fb6be76a8ae5ab97ae0cada9ce9c88675f1cea6c2bcf3da2c1ac1ae272994795&videoType=live&accountId=5650355166001&advertId=null&uaId=null&optinDeviceType=&optinAdTracking=0&tvid=null&pc=1000&deviceId=ab12092a-c770-41ee-b979-36712f130d49&mstatus=true&hl=zh&ozid=bfd6acf2-8319-4104-8745-35727d80eb77&vid=5652239841001&yo.hb=5000&pp=csai-web&custParams=rc%25253D1%252526y%25253D4%252526c%25253Dn%252526dpc%25253D2010%252526seriesid%25253D7NNS&y=4&c=n&dpc=2010&rc=1&yo.pp=aGRudHM9ZXhwPTE2MzgxNzE1ODF-YWNsPS8qfmhtYWM9NmNjZmU3NzZlNGZkNDFlYmI4YjRlMDVkOGY4YmQxMDkzN2NmYjMxMTMzZTRjZDE5ZTlkOTczOGNkOTBjZjhjNQ&yo.oh=Y3NtLWUtbjdhdXMtZWIudGxzMS55b3NwYWNlLmNvbQ==" >~/chanel7.txt 2>&1)
    if [[ "$GetPlayURL" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
    elif [[ "$GetPlayURL" == "curl"* ]]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    local PlayURL=$(cat ~/chanel7.txt | grep 'm3u8' | awk 'NR==2')
    rm -rf ~/chanel7.txt
    local Playlist=$(curl $useNIC $xForward -${1} ${ssll} -s --max-time 10 $PlayURL | grep akamaized | awk 'NR==2')
    local result=$(curl $useNIC $xForward -${1} ${ssll} -fsL --write-out %{http_code} --output /dev/null --max-time 10 "$Playlist")
    if [ "$result" = "000" ] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
    elif [ "$result" = "000" ]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r Channel 7:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_Channel10() {
    echo -n -e " Channel 10:\t\t\t\t->\c"
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} -sL --max-time 10 "https://10play.com.au/geo-web" 2>&1)
    if [[ "$tmpresult" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Channel 10:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
    elif [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r Channel 10:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'allow' | awk '{print $2}' | cut -f1 -d",")
    if [[ "$result" == "false" ]]; then
        echo -n -e "\r Channel 10:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [[ "$result" == "true" ]]; then
        echo -n -e "\r Channel 10:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Channel 10:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    return

}

function MediaUnlockTest_Funimation() {
    if [ "$is_busybox" == 1 ]; then
        tmp_file=$(mktemp)
    else
        tmp_file=$(mktemp --suffix=RRC)
    fi

    echo -n -e " Funimation:\t\t\t\t->\c"
    curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -ILs --max-time 10 --insecure "https://www.funimation.com" >${tmp_file}
    result=$(cat ${tmp_file} | awk 'NR==1' | awk '{print $2}')
    isHasRegion=$(cat ${tmp_file} | grep 'region=')
    if [[ "$1" == "6" ]]; then
        echo -n -e "\r Funimation:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [ "$result" = "000" ]; then
        echo -n -e "\r Funimation:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$result" = "403" ]; then
        echo -n -e "\r Funimation:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ -n "$isHasRegion" ]; then
        local region=$(cat ${tmp_file} | grep region= | awk '{print $2}' | cut -f1 -d";" | cut -f2 -d"=")
        echo -n -e "\r Funimation:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    fi

}

function MediaUnlockTest_Spotify() {
    local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://spclient.wg.spotify.com/signup/public/v1/account" -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -H "Accept-Language: en")
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep '"country":' | cut -f4 -d'"')
    local isLaunched=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep is_country_launched | cut -f1 -d',' | awk '{print $2}')
    local StatusCode=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep status | cut -f1 -d',' | awk '{print $2}')
    echo -n -e " Spotify Registration:\t\t\t->\c"

    if [ "$tmpresult" = "000" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    elif [ "$StatusCode" = "320" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    elif [ "$StatusCode" = "311" ] && [ "$isLaunched" = "true" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        return
    fi
}

function MediaUnlockTest_VideoMarket() {

    local token=$(curl -X POST -s "https://api-p.videomarket.jp/v2/authorize/access_token" -d 'grant_type=client_credentials&client_id=1eolxdrti3t58m2f2k8yi0kli105743b6f8c8295&client_secret=lco0nndn3l9tcbjdfdwlswmee105743b739cfb5a' | python -m json.tool 2>/dev/null | grep access_token | cut -f4 -d'"')
    local Auth="X-Authorization: $token"
    local playkey=$(curl -s -X POST "https://api-p.videomarket.jp/v2/api/play/keyissue" -d 'fullStoryId=118008001&playChromeCastFlag=false&loginFlag=0' -H "$Auth" | python -m json.tool 2>/dev/null | grep playKey | cut -f4 -d'"')
    local result=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://api-p.videomarket.jp/v2/api/play/keyauth?playKey=${playkey}&deviceType=3&bitRate=0&loginFlag=0&connType=" -H "$Auth")
    echo -n -e " VideoMarket:\t\t\t\t->\c"
    if [ "$result" = "000" ] && [ "$1" == "6" ]; then
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Red}IPv6 Not Supported${Font_Suffix}\n"
    elif [ "$result" = "000" ] && [ "$1" == "4" ]; then
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "200" ]; then
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "408" ]; then
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"    
    elif [ "$result" = "403" ]; then
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r VideoMarket:\t\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
    
}

function MediaUnlockTest_GYAO() {
	echo -n -e " GYAO!:\t\t\t\t\t->\c"
	if [ "$1" == "6" ]; then
        echo -n -e "\r GYAO!:\t\t\t\t\t${Font_Red}IPv6 Not Supported${Font_Suffix}\n"
		return
	fi
	local tmpresult=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -s --max-time 10 'https://gyao.yahoo.co.jp/apis/playback/graphql?appId=dj00aiZpPUNJeDh2cU1RazU3UCZzPWNvbnN1bWVyc2VjcmV0Jng9NTk-&query=%20query%20Playback(%24videoId%3A%20ID!%2C%20%24logicaAgent%3A%20LogicaAgent!%2C%20%24clientSpaceId%3A%20String!%2C%20%24os%3A%20Os!%2C%20%24device%3A%20Device!)%20%7B%20content(%20parameter%3A%20%7B%20contentId%3A%20%24videoId%20logicaAgent%3A%20%24logicaAgent%20clientSpaceId%3A%20%24clientSpaceId%20os%3A%20%24os%20device%3A%20%24device%20view%3A%20WEB%20%7D%20)%20%7B%20tracking%20%7B%20streamLog%20vrLog%20stLog%20%7D%20inStreamAd%20%7B%20forcePlayback%20source%20%7B%20__typename%20...%20on%20YjAds%20%7B%20ads%20%7B%20location%20time%20adRequests%20%7B%20__typename%20...%20on%20YjAdOnePfWeb%20%7B%20adDs%20placementCategoryId%20%7D%20...%20on%20YjAdOnePfProgrammaticWeb%20%7B%20adDs%20%7D%20...%20on%20YjAdAmobee%20%7B%20url%20%7D%20...%20on%20YjAdGam%20%7B%20url%20%7D%20%7D%20%7D%20%7D%20...%20on%20Vmap%20%7B%20url%20%7D%20...%20on%20CatchupVmap%20%7B%20url%20siteId%20%7D%20%7D%20%7D%20video%20%7B%20id%20title%20delivery%20%7B%20id%20drm%20%7D%20duration%20images%20%7B%20url%20width%20height%20%7D%20cpId%20playableAge%20maxPixel%20embeddingPermission%20playableAgents%20gyaoUrl%20%7D%20%7D%20%7D%20&variables=%7B%22videoId%22%3A%225fb4e68c-aef7-4f63-88e9-8cfeb35e9065%22%2C%22logicaAgent%22%3A%22PC_WEB%22%2C%22clientSpaceId%22%3A%221183050133%22%2C%22os%22%3A%22UNKNOWN%22%2C%22device%22%3A%22PC%22%7D')
	local result=$(echo $tmpresult | python -m json.tool 2>/dev/null)
	local isOutsideJapan=$(echo $result | grep "not in japan")
	if [ -n "result" ] && [ -n "$isOutsideJapan" ];then
		echo -n -e "\r GYAO!:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n"
	elif [ -n "result" ] && [ -z "$isOutsideJapan" ];then
		echo -n -e "\r GYAO!:\t\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
	else
		echo -n -e "\r GYAO!:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
	fi
}

function MediaUnlockTest_J:COM_ON_DEMAND() {
	echo -n -e " J:com On Demand:\t\t\t->\c"
	local result=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -fsL --write-out %{http_code} --output /dev/null --max-time 10 "https://id.zaq.ne.jp")
	if [ "$result" = "000" ]; then
        echo -n -e "\r J:com On Demand:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
    elif [ "$result" = "404" ]; then
        echo -n -e "\r J:com On Demand:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    elif [ "$result" = "403" ]; then
        echo -n -e "\r J:com On Demand:\t\t\t${Font_Red}No${Font_Suffix}\n"
    else
        echo -n -e "\r J:com On Demand:\t\t\t${Font_Red}Failed (Unexpected Result: $result)${Font_Suffix}\n"
    fi
}

function MediaUnlockTest_music.jp() {
	echo -n -e " music.jp:\t\t\t\t->\c"
	local result=$(curl $useNIC $xForward -${1} ${ssll} --user-agent "${UA_Browser}" -sL --max-time 10 "https://overseaauth.music-book.jp/globalIpcheck.js")
	if [ -n "$result" ]; then
        echo -n -e "\r music.jp:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r music.jp:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}
	
function NA_UnlockTest() {
    echo "===========[ North America ]==========="
    MediaUnlockTest_Fox ${1}
    MediaUnlockTest_HuluUS ${1}
    MediaUnlockTest_ESPNPlus ${1}
    MediaUnlockTest_EPIX ${1}
    MediaUnlockTest_Starz ${1}
    MediaUnlockTest_HBONow ${1}
    MediaUnlockTest_HBOMax ${1}
    MediaUnlockTest_BritBox ${1}
    MediaUnlockTest_NBATV ${1}
    MediaUnlockTest_FuboTV ${1}
    MediaUnlockTest_SlingTV ${1}
    MediaUnlockTest_PlutoTV ${1}
    MediaUnlockTest_AcornTV ${1}
    MediaUnlockTest_SHOWTIME ${1}
    MediaUnlockTest_encoreTVB ${1}
    MediaUnlockTest_CineMax ${1}
    MediaUnlockTest_Funimation ${1}
    MediaUnlockTest_DiscoveryPlus ${1}
    MediaUnlockTest_ParamountPlus ${1}
    MediaUnlockTest_PeacockTV ${1}
    MediaUnlockTest_ATTNOW ${1}
    ShowRegion CA
    MediaUnlockTest_CBCGem ${1}
    MediaUnlockTest_Crave ${1}
    echo "======================================="
}

function EU_UnlockTest() {
    echo "===============[ Europe ]=============="
    MediaUnlockTest_RakutenTV ${1}
    MediaUnlockTest_Funimation ${1}
    MediaUnlockTest_HBO_Nordic ${1}
    MediaUnlockTest_HBOGO_EUROPE ${1}
    ShowRegion GB
    MediaUnlockTest_SkyGo ${1}
    MediaUnlockTest_BritBox ${1}
    MediaUnlockTest_ITVHUB ${1}
    MediaUnlockTest_Channel4 ${1}
    MediaUnlockTest_Channel5 ${1}
    MediaUnlockTest_BBCiPLAYER ${1}
    MediaUnlockTest_DiscoveryPlusUK ${1}
    ShowRegion FR
    MediaUnlockTest_Salto ${1}
    MediaUnlockTest_CanalPlus ${1}
    MediaUnlockTest_Molotov ${1}
    ShowRegion DE
    MediaUnlockTest_Joyn ${1}
    MediaUnlockTest_SKY_DE ${1}
    MediaUnlockTest_ZDF ${1}
    ShowRegion NL
    MediaUnlockTest_NLZIET ${1}
    MediaUnlockTest_videoland ${1}
    MediaUnlockTest_NPO_Start_Plus ${1}
    ShowRegion ES
    MediaUnlockTest_HBO_Spain ${1}
    MediaUnlockTest_PANTAYA ${1}
    ShowRegion IT
    MediaUnlockTest_RaiPlay ${1}
    ShowRegion RU
    #MediaUnlockTest_MegogoTV ${1}
    MediaUnlockTest_Amediateka ${1}
    ShowRegion PT
    MediaUnlockTest_HBO_Portugal ${1}
    echo "======================================="
}

function HK_UnlockTest() {
    echo "=============[ Hong Kong ]============="
    MediaUnlockTest_NowE ${1}
    MediaUnlockTest_ViuTV ${1}
    MediaUnlockTest_MyTVSuper ${1}
    MediaUnlockTest_HBOGO_ASIA ${1}
    MediaUnlockTest_BilibiliHKMCTW ${1}
    echo "======================================="
}

function TW_UnlockTest() {
    echo "==============[ Taiwan ]==============="
    MediaUnlockTest_KKTV ${1}
    MediaUnlockTest_LiTV ${1}
    MediaUnlockTest_MyVideo ${1}
    MediaUnlockTest_4GTV ${1}
    MediaUnlockTest_LineTV.TW ${1}
    MediaUnlockTest_HamiVideo ${1}
    MediaUnlockTest_Catchplay ${1}
    MediaUnlockTest_HBOGO_ASIA ${1}
    MediaUnlockTest_BahamutAnime ${1}
    MediaUnlockTest_ElevenSportsTW ${1}
    MediaUnlockTest_BilibiliTW ${1}
    echo "======================================="
}

function JP_UnlockTest() {
    echo "===============[ Japan ]==============="
    MediaUnlockTest_DMM ${1}
    MediaUnlockTest_AbemaTV_IPTest ${1}
    MediaUnlockTest_Niconico ${1}
	MediaUnlockTest_music.jp ${1}
    MediaUnlockTest_Telasa ${1}
    MediaUnlockTest_Paravi ${1}
    MediaUnlockTest_unext ${1}
    MediaUnlockTest_HuluJP ${1}
    MediaUnlockTest_TVer ${1}
	MediaUnlockTest_GYAO ${1}
    MediaUnlockTest_wowow ${1}
    MediaUnlockTest_VideoMarket ${1}
    MediaUnlockTest_FOD ${1}
	MediaUnlockTest_Radiko ${1}
    MediaUnlockTest_DAM ${1}
    MediaUnlockTest_J:COM_ON_DEMAND ${1}
    ShowRegion Game
    MediaUnlockTest_Kancolle ${1}
    MediaUnlockTest_UMAJP ${1}
    MediaUnlockTest_KonosubaFD ${1}
    MediaUnlockTest_PCRJP ${1}
    MediaUnlockTest_WFJP ${1}
    MediaUnlockTest_ProjectSekai ${1}
    echo "======================================="
}

function Global_UnlockTest() {
    echo ""
    echo "============[ Multination ]============"
    MediaUnlockTest_Dazn ${1}
    MediaUnlockTest_HotStar ${1}
    MediaUnlockTest_DisneyPlus ${1}
    MediaUnlockTest_Netflix ${1}
    MediaUnlockTest_YouTube_Premium ${1}
    MediaUnlockTest_PrimeVideo_Region ${1}
    MediaUnlockTest_TVBAnywhere ${1}
    MediaUnlockTest_iQYI_Region ${1}
    MediaUnlockTest_Viu.com ${1}
    MediaUnlockTest_YouTube_CDN ${1}
    MediaUnlockTest_NetflixCDN ${1}
    MediaUnlockTest_Spotify ${1}
    GameTest_Steam ${1}
    echo "======================================="
}

function SA_UnlockTest() {
    echo "===========[ South America ]==========="
    MediaUnlockTest_StarPlus ${1}
    MediaUnlockTest_HBOMax ${1}
    MediaUnlockTest_DirecTVGO ${1}
    MediaUnlockTest_Funimation ${1}
    echo "======================================="
}

function OA_UnlockTest() {
    echo "==============[ Oceania ]=============="
    MediaUnlockTest_NBATV ${1}
    MediaUnlockTest_AcornTV ${1}
    MediaUnlockTest_SHOWTIME ${1}
    MediaUnlockTest_BritBox ${1}
    MediaUnlockTest_Funimation ${1}
    MediaUnlockTest_ParamountPlus ${1}
    ShowRegion AU
    MediaUnlockTest_Stan ${1}
    MediaUnlockTest_Binge ${1}
    MediaUnlockTest_Docplay ${1}
    MediaUnlockTest_Channel7 ${1}
    MediaUnlockTest_Channel9 ${1}
    MediaUnlockTest_Channel10 ${1}
    MediaUnlockTest_ABCiView ${1}
    MediaUnlockTest_KayoSports ${1}
    MediaUnlockTest_OptusSports ${1}
    MediaUnlockTest_SBSonDemand ${1}
    ShowRegion NZ
    MediaUnlockTest_NeonTV ${1}
    MediaUnlockTest_SkyGONZ ${1}
    MediaUnlockTest_ThreeNow ${1}
    MediaUnlockTest_MaoriTV ${1}
    echo "======================================="
}

function Sport_UnlockTest() {
    echo "===============[ Sport ]==============="
    MediaUnlockTest_Dazn ${1}
    MediaUnlockTest_StarPlus ${1}
    MediaUnlockTest_ESPNPlus ${1}
    MediaUnlockTest_NBATV ${1}
    MediaUnlockTest_FuboTV ${1}
    MediaUnlockTest_MolaTV ${1}
    MediaUnlockTest_SetantaSports ${1}
    MediaUnlockTest_ElevenSportsTW ${1}
    MediaUnlockTest_OptusSports ${1}
    MediaUnlockTest_BeinConnect ${1}
    MediaUnlockTest_EurosportRO ${1}

    echo "======================================="
}

function CheckV4() {
    if [[ "$language" == "e" ]]; then
        if [[ "$NetworkType" == "6" ]]; then
            isv4=0
            echo -e "${Font_SkyBlue}User Choose to Test Only IPv6 Results, Skipping IPv4 Testing...${Font_Suffix}"
        else
            echo -e " ${Font_SkyBlue}** Checking Results Under IPv4${Font_Suffix} "
            echo "--------------------------------"
            echo -e " ${Font_SkyBlue}** Your Network Provider: ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix} "
            check4=$(ping 1.1.1.1 -c 1 2>&1)
            if [[ "$check4" != *"unreachable"* ]] && [[ "$check4" != *"Unreachable"* ]]; then
                isv4=1
            else
                echo -e "${Font_SkyBlue}No IPv4 Connectivity Found, Abort IPv4 Testing...${Font_Suffix}"
                isv4=0
            fi

            echo ""
        fi
    else
        if [[ "$NetworkType" == "6" ]]; then
            isv4=0
            echo -e "${Font_SkyBlue}用户选择只检测IPv6结果，跳过IPv4检测...${Font_Suffix}"
        else
            echo -e " ${Font_SkyBlue}** 正在测试IPv4解锁情况${Font_Suffix} "
            echo "--------------------------------"
            echo -e " ${Font_SkyBlue}** 您的网络为: ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix} "
            check4=$(ping 1.1.1.1 -c 1 2>&1)
            if [[ "$check4" != *"unreachable"* ]] && [[ "$check4" != *"Unreachable"* ]]; then
                isv4=1
            else
                echo -e "${Font_SkyBlue}当前主机不支持IPv4,跳过...${Font_Suffix}"
                isv4=0
            fi

            echo ""
        fi
    fi
}

function CheckV6() {
    if [[ "$language" == "e" ]]; then
        if [[ "$NetworkType" == "4" ]]; then
            isv6=0
            echo -e "${Font_SkyBlue}User Choose to Test Only IPv4 Results, Skipping IPv6 Testing...${Font_Suffix}"
        else
            check6_1=$(curl $useNIC -fsL --write-out %{http_code} --output /dev/null --max-time 10 ipv6.google.com)
            check6_2=$(curl $useNIC -fsL --write-out %{http_code} --output /dev/null --max-time 10 ipv6.ip.sb)
            if [[ "$check6_1" -ne "000" ]] || [[ "$check6_2" -ne "000" ]]; then
                echo ""
                echo ""
                echo -e " ${Font_SkyBlue}** Checking Results Under IPv6${Font_Suffix} "
                echo "--------------------------------"
                echo -e " ${Font_SkyBlue}** Your Network Provider: ${local_isp6} (${local_ipv6_asterisk})${Font_Suffix} "
                isv6=1
            else
                echo -e "${Font_SkyBlue}No IPv6 Connectivity Found, Abort IPv6 Testing...${Font_Suffix}"
                isv6=0
            fi
            echo -e ""
        fi

    else
        if [[ "$NetworkType" == "4" ]]; then
            isv6=0
            echo -e "${Font_SkyBlue}用户选择只检测IPv4结果，跳过IPv6检测...${Font_Suffix}"
        else
            check6_1=$(curl $useNIC -fsL --write-out %{http_code} --output /dev/null --max-time 10 ipv6.google.com)
            check6_2=$(curl $useNIC -fsL --write-out %{http_code} --output /dev/null --max-time 10 ipv6.ip.sb)
            if [[ "$check6_1" -ne "000" ]] || [[ "$check6_2" -ne "000" ]]; then
                echo ""
                echo ""
                echo -e " ${Font_SkyBlue}** 正在测试IPv6解锁情况${Font_Suffix} "
                echo "--------------------------------"
                echo -e " ${Font_SkyBlue}** 您的网络为: ${local_isp6} (${local_ipv6_asterisk})${Font_Suffix} "
                isv6=1
            else
                echo -e "${Font_SkyBlue}当前主机不支持IPv6,跳过...${Font_Suffix}"
                isv6=0
            fi
            echo -e ""
        fi
    fi
}

function Goodbye() {
    if [ "${num}" == 1 ]; then
        ADN=TW
    else
        ADN=$(echo $(($RANDOM % 2 + 1)))
    fi

    if [[ "$language" == "e" ]]; then
        echo -e "${Font_Green}Testing Done! Thanks for Using This Script! ${Font_Suffix}"
        echo -e ""
        echo -e "${Font_Yellow}Number of Script Runs for Today: ${TodayRunTimes}; Total Number of Script Runs: ${TotalRunTimes} ${Font_Suffix}"
        echo -e ""
        echo -e "========================================================="
        echo -e "${Font_Red}If you found this script helpful, you can but me a coffee${Font_Suffix}"
        echo -e ""
        echo -e "LTC: LQD4S6Y5bu3bHX6hx8ASsGHVfaqFGFNTbx"
        echo -e "========================================================="
    else
        echo -e "${Font_Green}本次测试已结束，感谢使用此脚本 ${Font_Suffix}"
        echo -e ""
        echo -e "${Font_Yellow}检测脚本当天运行次数: ${TodayRunTimes}; 共计运行次数: ${TotalRunTimes} ${Font_Suffix}"
        echo -e ""
        bash <(curl -s https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/AD/AD${ADN})
        echo -e ""
        echo -e ""
        echo -e ""
        echo -e ""
        echo -e "${Font_Yellow}由于大部分 IP 的 Tiktok 检测时间过长，已将该检测移除出脚本${Font_Suffix}"
        echo -e "${Font_Yellow}需要检测 Tiktok 区域请移步项目: https://github.com/lmc999/TikTokCheck${Font_Suffix}"

    fi
}

function ScriptTitle() {
    if [[ "$language" == "e" ]]; then
        echo -e " [Stream Platform & Game Region Restriction Test]"
        echo ""
        echo -e "${Font_Green}Github Repository:${Font_Suffix} ${Font_Yellow} https://github.com/lmc999/RegionRestrictionCheck ${Font_Suffix}"
        echo -e "${Font_Green}Telegram Discussion Group:${Font_Suffix} ${Font_Yellow} https://t.me/gameaccelerate ${Font_Suffix}"
        echo -e "${Font_Purple}Supporting OS: CentOS 6+, Ubuntu 14.04+, Debian 8+, MacOS, Android (Termux), iOS (iSH)${Font_Suffix}"
        echo ""
        echo -e " ** Test Starts At: $(date)"
        echo ""
    else
        echo -e " [流媒体平台及游戏区域限制测试]"
        echo ""
        echo -e "${Font_Green}项目地址${Font_Suffix} ${Font_Yellow}https://github.com/lmc999/RegionRestrictionCheck ${Font_Suffix}"
        echo -e "${Font_Green}BUG反馈或使用交流可加TG群组${Font_Suffix} ${Font_Yellow}https://t.me/gameaccelerate ${Font_Suffix}"
        echo -e "${Font_Purple}脚本适配OS: CentOS 6+, Ubuntu 14.04+, Debian 8+, MacOS, Android (Termux), iOS (iSH)${Font_Suffix}"
        echo ""
        echo -e " ** 测试时间: $(date)"
        echo ""
    fi
}
# ScriptTitle

function Start() {
    if [[ "$language" == "e" ]]; then
        echo -e "${Font_Blue}Please Select Test Region or Press ENTER to Test All Regions${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [1]: [ Multination + Taiwan ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [2]: [ Multination + Hong Kong ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [3]: [ Multination + Japan ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [4]: [ Multination + North America ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [5]: [ Multination + South America ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [6]: [ Multination + Europe ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [7]: [ Multination + Oceania ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number  [0]: [ Multination Only ]${Font_Suffix}"
        echo -e "${Font_SkyBlue}Input Number [99]: [ Sport Platforms ]${Font_Suffix}"
        read -p "Please Input the Correct Number or Press ENTER:" num
    else
        echo -e "${Font_Blue}请选择检测项目，直接按回车将进行全区域检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [1]: [ 跨国平台+台湾平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [2]: [ 跨国平台+香港平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [3]: [ 跨国平台+日本平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [4]: [ 跨国平台+北美平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [5]: [ 跨国平台+南美平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [6]: [ 跨国平台+欧洲平台 ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [7]: [跨国平台+大洋洲平台]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字  [0]: [   只进行跨国平台  ]检测${Font_Suffix}"
        echo -e "${Font_SkyBlue}输入数字 [99]: [   体育直播平台    ]检测${Font_Suffix}"
        echo -e "${Font_Purple}输入数字 [69]: [   广告推广投放    ]咨询${Font_Suffix}"
        read -p "请输入正确数字或直接按回车:" num
    fi
}
# Start

function RunScript() {
    # if [[ -n "${num}" ]]; then
    #     if [[ "$num" -eq 1 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             TW_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             TW_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 2 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             HK_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             HK_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 3 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             JP_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             JP_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 4 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             NA_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             NA_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 5 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             SA_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             SA_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 6 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             EU_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             EU_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 7 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #             OA_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #             OA_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 99 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Sport_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Sport_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 0 ]]; then
    #         clear
    #         ScriptTitle
    #         CheckV4
    #         if [[ "$isv4" -eq 1 ]]; then
    #             Global_UnlockTest 4
    #         fi
    #         CheckV6
    #         if [[ "$isv6" -eq 1 ]]; then
    #             Global_UnlockTest 6
    #         fi
    #         Goodbye

    #     elif [[ "$num" -eq 69 ]]; then
    #         clear
    #         ScriptTitle
    #         echo ""
    #         echo ""
    #         echo -e "${Font_Red}**************************${Font_Suffix}"
    #         echo -e "${Font_Red}*                        *${Font_Suffix}"
    #         echo -e "${Font_Red}*${Font_Suffix} 广告招租               ${Font_Red}*${Font_Suffix}"
    #         echo -e "${Font_Red}*${Font_Suffix} 请联系：@reidschat_bot ${Font_Red}*${Font_Suffix}"
    #         echo -e "${Font_Red}*                        *${Font_Suffix}"
    #         echo -e "${Font_Red}**************************${Font_Suffix}"

    #     else
    #         echo -e "${Font_Red}请重新执行脚本并输入正确号码${Font_Suffix}"
    #         echo -e "${Font_Red}Please Re-run the Script with Correct Number Input${Font_Suffix}"
    #         return
    #     fi
    # else
    # clear
    ScriptTitle
    CheckV4
    if [[ "$isv4" -eq 1 ]]; then
        Global_UnlockTest 4
        TW_UnlockTest 4
        HK_UnlockTest 4
        JP_UnlockTest 4
        NA_UnlockTest 4
        SA_UnlockTest 4
        EU_UnlockTest 4
        OA_UnlockTest 4
    fi
    CheckV6
    if [[ "$isv6" -eq 1 ]]; then
        Global_UnlockTest 6
        TW_UnlockTest 6
        HK_UnlockTest 6
        JP_UnlockTest 6
        NA_UnlockTest 6
        SA_UnlockTest 6
        EU_UnlockTest 6
        OA_UnlockTest 6
    fi
        # Goodbye
    # fi
}

RunScript

#################
# 三网测速脚本
#################

#!/usr/bin/env bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE="\033[0;35m"
CYAN='\033[0;36m'
PLAIN='\033[0m'

checkroot(){
	[[ $EUID -ne 0 ]] && echo -e "${RED}请使用 root 用户运行本脚本！${PLAIN}" && exit 1
}

checksystem() {
	if [ -f /etc/redhat-release ]; then
	    release="centos"
	elif cat /etc/issue | grep -Eqi "debian"; then
	    release="debian"
	elif cat /etc/issue | grep -Eqi "ubuntu"; then
	    release="ubuntu"
	elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
	    release="centos"
	elif cat /proc/version | grep -Eqi "debian"; then
	    release="debian"
	elif cat /proc/version | grep -Eqi "ubuntu"; then
	    release="ubuntu"
	elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
	    release="centos"
	fi
}

checkpython() {
	if  [ ! -e '/usr/bin/python' ]; then
	        echo "正在安装 Python"
	            if [ "${release}" == "centos" ]; then
	            		yum update > /dev/null 2>&1
	                    yum -y install python > /dev/null 2>&1
	                else
	                	apt-get update > /dev/null 2>&1
	                    apt-get -y install python > /dev/null 2>&1
	                fi
	        
	fi
}



checkspeedtest() {
	if  [ ! -e './speedtest-cli/speedtest' ]; then
		echo "正在安装 Speedtest-cli"
		#wget --no-check-certificate -qO speedtest.tgz https://bintray.com/ookla/download/download_file?file_path=ookla-speedtest-1.0.0-$(uname -m)-linux.tgz > /dev/null 2>&1
		wget --no-check-certificate -qO speedtest.tgz https://filedown.me/Linux/Tool/speedtest_cli/ookla-speedtest-1.0.0-$(uname -m)-linux.tgz > /dev/null 2>&1
	fi
	mkdir -p speedtest-cli && tar zxvf speedtest.tgz -C ./speedtest-cli/ > /dev/null 2>&1 && chmod a+rx ./speedtest-cli/speedtest
}

speed_test(){
	speedLog="./speedtest.log"
	true > $speedLog
		speedtest-cli/speedtest -p no -s $1 --accept-license --accept-gdpr > $speedLog 2>&1
		is_upload=$(cat $speedLog | grep 'Upload')
		if [[ ${is_upload} ]]; then
	        local REDownload=$(cat $speedLog | awk -F ' ' '/Download/{print $3}')
	        local reupload=$(cat $speedLog | awk -F ' ' '/Upload/{print $3}')
	        local relatency=$(cat $speedLog | awk -F ' ' '/Latency/{print $2}')
	        
			local nodeID=$1
			local nodeLocation=$2
			local nodeISP=$3
			
			strnodeLocation="${nodeLocation}　　　　　　"
			LANG=C
			#echo $LANG
			
			temp=$(echo "${REDownload}" | awk -F ' ' '{print $1}')
	        if [[ $(awk -v num1=${temp} -v num2=0 'BEGIN{print(num1>num2)?"1":"0"}') -eq 1 ]]; then
	        	printf "${RED}%-6s${YELLOW}%s%s${GREEN}%-24s${CYAN}%s%-10s${BLUE}%s%-10s${PURPLE}%-8s${PLAIN}\n" "${nodeID}"  "${nodeISP}" "|" "${strnodeLocation:0:24}" "↑ " "${reupload}" "↓ " "${REDownload}" "${relatency}" | tee -a $log
			fi
		else
	        local cerror="ERROR"
		fi
}

preinfo() {
	echo "——————————————————————————————————————————————————————————"
	echo " SuperSpeed 全面测速修复版. By UXH & ernisn & oooldking"
	echo " 节点更新: 2020/06/19 | 脚本更新: 2021/12/23"
	echo " Github: https://github.com/uxh/superspeed"
	# echo "——————————————————————————————————————————————————————————"
}

selecttest() {
	echo -e "  测速类型:    ${GREEN}0.${PLAIN} 取消测速    ${GREEN}1.${PLAIN} 三网测速    ${GREEN}2.${PLAIN} 详细测速"
	echo -ne "               ${GREEN}3.${PLAIN} 电信节点    ${GREEN}4.${PLAIN} 联通节点    ${GREEN}5.${PLAIN} 移动节点"
	while :; do echo
			read -p "  请输入数字选择测速类型: " selection
			if [[ ! $selection =~ ^[1-5]$ ]]; then
					echo -ne "  ${RED}输入错误${PLAIN}, 请输入正确的数字!"
			else
					break   
			fi
	done
}

runtest() {
	[[ ${selection} == 0 ]] && exit 1

	if [[ ${selection} == 1 ]]; then
		echo "——————————————————————————————————————————————————————————"
		echo "ID    测速服务器信息       上传/Mbps   下载/Mbps   延迟/ms"
		start=$(date +%s) 

		 speed_test '3633' '上海' '电信'
		 speed_test '24012' '内蒙古呼和浩特' '电信'
		 speed_test '27377' '北京５Ｇ' '电信'
		 speed_test '29026' '四川成都' '电信'
		# speed_test '29071' '四川成都' '电信'
		 speed_test '17145' '安徽合肥５Ｇ' '电信'
		 speed_test '27594' '广东广州５Ｇ' '电信'
		# speed_test '27810' '广西南宁' '电信'
		 speed_test '27575' '新疆乌鲁木齐' '电信'
		# speed_test '26352' '江苏南京５Ｇ' '电信'
		 speed_test '5396' '江苏苏州５Ｇ' '电信'
		# speed_test '5317' '江苏连云港５Ｇ' '电信'
		# speed_test '7509' '浙江杭州' '电信'
		 speed_test '23844' '湖北武汉' '电信'
		 speed_test '29353' '湖北武汉５Ｇ' '电信'
		 speed_test '28225' '湖南长沙５Ｇ' '电信'
		 speed_test '3973' '甘肃兰州' '电信'
		# speed_test '19076' '重庆' '电信'
		#***
		# speed_test '21005' '上海' '联通'
		 speed_test '24447' '上海５Ｇ' '联通'
		# speed_test '5103' '云南昆明' '联通'
		 speed_test '5145' '北京' '联通'
		# speed_test '5505' '北京' '联通'
		# speed_test '9484' '吉林长春' '联通'
		 speed_test '2461' '四川成都' '联通'
		 speed_test '27154' '天津５Ｇ' '联通'
		# speed_test '5509' '宁夏银川' '联通'
		# speed_test '5724' '安徽合肥' '联通'
		# speed_test '5039' '山东济南' '联通'
		 speed_test '26180' '山东济南５Ｇ' '联通'
		 speed_test '26678' '广东广州５Ｇ' '联通'
		# speed_test '16192' '广东深圳' '联通'
		# speed_test '6144' '新疆乌鲁木齐' '联通'
		 speed_test '13704' '江苏南京' '联通'
		 speed_test '5485' '湖北武汉' '联通'
		# speed_test '26677' '湖南株洲' '联通'
		 speed_test '4870' '湖南长沙' '联通'
		# speed_test '4690' '甘肃兰州' '联通'
		# speed_test '4884' '福建福州' '联通'
		# speed_test '31985' '重庆' '联通'
		 speed_test '4863' '陕西西安' '联通'
		#***
		# speed_test '30154' '上海' '移动'
		# speed_test '25637' '上海５Ｇ' '移动'
		# speed_test '26728' '云南昆明' '移动'
		# speed_test '27019' '内蒙古呼和浩特' '移动'
		 speed_test '30232' '内蒙呼和浩特５Ｇ' '移动'
		# speed_test '30293' '内蒙古通辽５Ｇ' '移动'
		 speed_test '25858' '北京' '移动'
		 speed_test '16375' '吉林长春' '移动'
		# speed_test '24337' '四川成都' '移动'
		 speed_test '17184' '天津５Ｇ' '移动'
		# speed_test '26940' '宁夏银川' '移动'
		# speed_test '31815' '宁夏银川' '移动'
		# speed_test '26404' '安徽合肥５Ｇ' '移动'
		 speed_test '27151' '山东临沂５Ｇ' '移动'
		# speed_test '25881' '山东济南５Ｇ' '移动'
		# speed_test '27100' '山东青岛５Ｇ' '移动'
		# speed_test '26501' '山西太原５Ｇ' '移动'
		 speed_test '31520' '广东中山' '移动'
		# speed_test '6611' '广东广州' '移动'
		# speed_test '4515' '广东深圳' '移动'
		# speed_test '15863' '广西南宁' '移动'
		# speed_test '16858' '新疆乌鲁木齐' '移动'
		 speed_test '26938' '新疆乌鲁木齐５Ｇ' '移动'
		# speed_test '17227' '新疆和田' '移动'
		# speed_test '17245' '新疆喀什' '移动'
		# speed_test '17222' '新疆阿勒泰' '移动'
		# speed_test '27249' '江苏南京５Ｇ' '移动'
		# speed_test '21845' '江苏常州５Ｇ' '移动'
		# speed_test '26850' '江苏无锡５Ｇ' '移动'
		# speed_test '17320' '江苏镇江５Ｇ' '移动'
		 speed_test '25883' '江西南昌５Ｇ' '移动'
		# speed_test '17223' '河北石家庄' '移动'
		# speed_test '26331' '河南郑州５Ｇ' '移动'
		# speed_test '6715' '浙江宁波５Ｇ' '移动'
		# speed_test '4647' '浙江杭州' '移动'
		# speed_test '16503' '海南海口' '移动'
		# speed_test '28491' '湖南长沙５Ｇ' '移动'
		# speed_test '16145' '甘肃兰州' '移动'
		 speed_test '16171' '福建福州' '移动'
		# speed_test '18444' '西藏拉萨' '移动'
		 speed_test '16398' '贵州贵阳' '移动'
		 speed_test '25728' '辽宁大连' '移动'
		# speed_test '16167' '辽宁沈阳' '移动'
		# speed_test '17584' '重庆' '移动'
		# speed_test '26380' '陕西西安' '移动'
		# speed_test '29105' '陕西西安５Ｇ' '移动'
		# speed_test '29083' '青海西宁５Ｇ' '移动'
		# speed_test '26656' '黑龙江哈尔滨' '移动'

		end=$(date +%s)  
		rm -rf speedtest*
		echo "——————————————————————————————————————————————————————————"
		time=$(( $end - $start ))
		if [[ $time -gt 60 ]]; then
			min=$(expr $time / 60)
			sec=$(expr $time % 60)
			echo -ne "  测试完成, 本次测速耗时: ${min} 分 ${sec} 秒"
		else
			echo -ne "  测试完成, 本次测速耗时: ${time} 秒"
		fi
		echo -ne "\n  当前时间: "
		echo $(TZ=UTC-8 date +%Y-%m-%d" "%H:%M:%S)
		echo -e "  ${GREEN}# 三网测速中为避免节点数不均及测试过久，每部分未使用所${PLAIN}"
		echo -e "  ${GREEN}# 有节点，如果需要使用全部节点，可分别选择三网节点检测${PLAIN}"
	fi

	if [[ ${selection} == 2 ]]; then
		echo "——————————————————————————————————————————————————————————"
		echo "ID    测速服务器信息       上传/Mbps   下载/Mbps   延迟/ms"
		start=$(date +%s) 

		 speed_test '3633' '上海' '电信'
		#  speed_test '24012' '内蒙古呼和浩特' '电信'
		#  speed_test '27377' '北京５Ｇ' '电信'
		#  speed_test '29026' '四川成都' '电信'
		 speed_test '29071' '四川成都' '电信'
		 speed_test '17145' '安徽合肥５Ｇ' '电信'
		 speed_test '27594' '广东广州５Ｇ' '电信'
		#  speed_test '27810' '广西南宁' '电信'
		#  speed_test '27575' '新疆乌鲁木齐' '电信'
		 speed_test '26352' '江苏南京５Ｇ' '电信'
		#  speed_test '5396' '江苏苏州５Ｇ' '电信'
		#  speed_test '5317' '江苏连云港５Ｇ' '电信'
		 speed_test '36663' '江苏镇江５Ｇ' '电信'
		#  speed_test '7509' '浙江杭州' '电信'
		 speed_test '23844' '湖北武汉' '电信'
		#  speed_test '29353' '湖北武汉５Ｇ' '电信'
		 speed_test '28225' '湖南长沙５Ｇ' '电信'
		 speed_test '3973' '甘肃兰州' '电信'
		#  speed_test '19076' '重庆' '电信'
		 speed_test '35722' '天津' '电信'
		#  speed_test '34115' '天津５Ｇ' '电信'
		#  speed_test '41355' '河南郑州５Ｇ' '电信'
		#  speed_test '34988' '辽宁沈阳５Ｇ' '电信'

		#  speed_test '21005' '上海' '联通'
		 speed_test '24447' '上海５Ｇ' '联通'
		#  speed_test '5103' '云南昆明' '联通'
		#  speed_test '5145' '北京' '联通'
		#  speed_test '5505' '北京' '联通'
		#  speed_test '9484' '吉林长春' '联通'
		#  speed_test '2461' '四川成都' '联通'
		#  speed_test '27154' '天津５Ｇ' '联通'
		#  speed_test '5509' '宁夏银川' '联通'
		#  speed_test '5724' '安徽合肥' '联通'
		#  speed_test '5039' '山东济南' '联通'
		#  speed_test '26180' '山东济南５Ｇ' '联通'
		#  speed_test '26678' '广东广州５Ｇ' '联通'
		#  speed_test '16192' '广东深圳' '联通'
		#  speed_test '6144' '新疆乌鲁木齐' '联通'
		#  speed_test '13704' '江苏南京' '联通'
		#  speed_test '5485' '湖北武汉' '联通'
		#  speed_test '41009' '湖北武汉５Ｇ' '联通'
		#  speed_test '26677' '湖南株洲' '联通'
		 speed_test '4870' '湖南长沙' '联通'
		#  speed_test '4690' '甘肃兰州' '联通'
		#  speed_test '4884' '福建福州' '联通'
		#  speed_test '31985' '重庆' '联通'
		#  speed_test '4863' '陕西西安' '联通'

		#  speed_test '30154' '上海' '移动'
		 speed_test '25637' '上海５Ｇ' '移动'
		#  speed_test '26728' '云南昆明' '移动'
		#  speed_test '27019' '内蒙古呼和浩特' '移动'
		#  speed_test '30232' '内蒙呼和浩特５Ｇ' '移动'
		#  speed_test '30293' '内蒙古通辽５Ｇ' '移动'
		#  speed_test '25858' '北京' '移动'
		#  speed_test '16375' '吉林长春' '移动'
		#  speed_test '24337' '四川成都' '移动'
		#  speed_test '17184' '天津５Ｇ' '移动'
		#  speed_test '26940' '宁夏银川' '移动'
		#  speed_test '31815' '宁夏银川' '移动'
		 speed_test '26404' '安徽合肥５Ｇ' '移动'
		#  speed_test '27151' '山东临沂５Ｇ' '移动'
		#  speed_test '25881' '山东济南５Ｇ' '移动'
		#  speed_test '27100' '山东青岛５Ｇ' '移动'
		#  speed_test '26501' '山西太原５Ｇ' '移动'
		#  speed_test '31520' '广东中山' '移动'
		#  speed_test '6611' '广东广州' '移动'
		#  speed_test '4515' '广东深圳' '移动'
		#  speed_test '15863' '广西南宁' '移动'
		#  speed_test '16858' '新疆乌鲁木齐' '移动'
		#  speed_test '26938' '新疆乌鲁木齐５Ｇ' '移动'
		#  speed_test '17227' '新疆和田' '移动'
		#  speed_test '17245' '新疆喀什' '移动'
		#  speed_test '17222' '新疆阿勒泰' '移动'
		#  speed_test '27249' '江苏南京５Ｇ' '移动'
		#  speed_test '21845' '江苏常州５Ｇ' '移动'
		#  speed_test '32291' '江苏常州５Ｇ' '移动'
		#  speed_test '40131' '江苏苏州５Ｇ' '移动'
		#  speed_test '26850' '江苏无锡５Ｇ' '移动'
		#  speed_test '17320' '江苏镇江５Ｇ' '移动'
		#  speed_test '25883' '江西南昌５Ｇ' '移动'
		#  speed_test '17223' '河北石家庄' '移动'
		#  speed_test '26331' '河南郑州５Ｇ' '移动'
		 speed_test '6715' '浙江宁波５Ｇ' '移动'
		#  speed_test '4647' '浙江杭州' '移动'
		#  speed_test '16503' '海南海口' '移动'
		#  speed_test '28491' '湖南长沙５Ｇ' '移动'
		#  speed_test '16145' '甘肃兰州' '移动'
		 speed_test '16171' '福建福州' '移动'
		#  speed_test '18444' '西藏拉萨' '移动'
		#  speed_test '16398' '贵州贵阳' '移动'
		#  speed_test '25728' '辽宁大连' '移动'
		#  speed_test '16167' '辽宁沈阳' '移动'
		#  speed_test '17584' '重庆' '移动'
		#  speed_test '26380' '陕西西安' '移动'
		#  speed_test '29105' '陕西西安５Ｇ' '移动'
		#  speed_test '29083' '青海西宁５Ｇ' '移动'
		#  speed_test '26656' '黑龙江哈尔滨' '移动'

		end=$(date +%s)  
		rm -rf speedtest*
		echo "——————————————————————————————————————————————————————————"
		time=$(( $end - $start ))
		if [[ $time -gt 60 ]]; then
			min=$(expr $time / 60)
			sec=$(expr $time % 60)
			echo -ne "  测试完成, 本次测速耗时: ${min} 分 ${sec} 秒"
		else
			echo -ne "  测试完成, 本次测速耗时: ${time} 秒"
		fi
		echo -ne "\n  当前时间: "
		echo $(TZ=UTC-8 date +%Y-%m-%d" "%H:%M:%S)
	fi

	if [[ ${selection} == 3 ]]; then
		echo "——————————————————————————————————————————————————————————"
		echo "ID    测速服务器信息       上传/Mbps   下载/Mbps   延迟/ms"
		start=$(date +%s) 

		 speed_test '3633' '上海' '电信'
		 speed_test '24012' '内蒙古呼和浩特' '电信'
		 speed_test '27377' '北京５Ｇ' '电信'
		 speed_test '29026' '四川成都' '电信'
		 speed_test '29071' '四川成都' '电信'
		 speed_test '17145' '安徽合肥５Ｇ' '电信'
		 speed_test '27594' '广东广州５Ｇ' '电信'
		 speed_test '27810' '广西南宁' '电信'
		 speed_test '27575' '新疆乌鲁木齐' '电信'
		 speed_test '26352' '江苏南京５Ｇ' '电信'
		 speed_test '5396' '江苏苏州５Ｇ' '电信'
		 speed_test '5317' '江苏连云港５Ｇ' '电信'
		 speed_test '36663' '江苏镇江５Ｇ' '电信'
		 speed_test '7509' '浙江杭州' '电信'
		 speed_test '23844' '湖北武汉' '电信'
		 speed_test '29353' '湖北武汉５Ｇ' '电信'
		 speed_test '28225' '湖南长沙５Ｇ' '电信'
		 speed_test '3973' '甘肃兰州' '电信'
		 speed_test '19076' '重庆' '电信'
		 speed_test '35722' '天津' '电信'
		 speed_test '34115' '天津５Ｇ' '电信'
		 speed_test '41355' '河南郑州５Ｇ' '电信'
		 speed_test '34988' '辽宁沈阳５Ｇ' '电信'

		end=$(date +%s)  
		rm -rf speedtest*
		echo "——————————————————————————————————————————————————————————"
		time=$(( $end - $start ))
		if [[ $time -gt 60 ]]; then
			min=$(expr $time / 60)
			sec=$(expr $time % 60)
			echo -ne "  测试完成, 本次测速耗时: ${min} 分 ${sec} 秒"
		else
			echo -ne "  测试完成, 本次测速耗时: ${time} 秒"
		fi
		echo -ne "\n  当前时间: "
		echo $(TZ=UTC-8 date +%Y-%m-%d" "%H:%M:%S)
	fi

	if [[ ${selection} == 4 ]]; then
		echo "——————————————————————————————————————————————————————————"
		echo "ID    测速服务器信息       上传/Mbps   下载/Mbps   延迟/ms"
		start=$(date +%s) 

		 speed_test '21005' '上海' '联通'
		 speed_test '24447' '上海５Ｇ' '联通'
		 speed_test '5103' '云南昆明' '联通'
		 speed_test '5145' '北京' '联通'
		 speed_test '5505' '北京' '联通'
		 speed_test '9484' '吉林长春' '联通'
		 speed_test '2461' '四川成都' '联通'
		 speed_test '27154' '天津５Ｇ' '联通'
		 speed_test '5509' '宁夏银川' '联通'
		 speed_test '5724' '安徽合肥' '联通'
		 speed_test '5039' '山东济南' '联通'
		 speed_test '26180' '山东济南５Ｇ' '联通'
		 speed_test '26678' '广东广州５Ｇ' '联通'
		 speed_test '16192' '广东深圳' '联通'
		 speed_test '6144' '新疆乌鲁木齐' '联通'
		 speed_test '13704' '江苏南京' '联通'
		 speed_test '5485' '湖北武汉' '联通'
		 speed_test '41009' '湖北武汉５Ｇ' '联通'
		 speed_test '26677' '湖南株洲' '联通'
		 speed_test '4870' '湖南长沙' '联通'
		 speed_test '4690' '甘肃兰州' '联通'
		 speed_test '4884' '福建福州' '联通'
		 speed_test '31985' '重庆' '联通'
		 speed_test '4863' '陕西西安' '联通'

		end=$(date +%s)  
		rm -rf speedtest*
		echo "——————————————————————————————————————————————————————————"
		time=$(( $end - $start ))
		if [[ $time -gt 60 ]]; then
			min=$(expr $time / 60)
			sec=$(expr $time % 60)
			echo -ne "  测试完成, 本次测速耗时: ${min} 分 ${sec} 秒"
		else
			echo -ne "  测试完成, 本次测速耗时: ${time} 秒"
		fi
		echo -ne "\n  当前时间: "
		echo $(TZ=UTC-8 date +%Y-%m-%d" "%H:%M:%S)
	fi

	if [[ ${selection} == 5 ]]; then
		echo "——————————————————————————————————————————————————————————"
		echo "ID    测速服务器信息       上传/Mbps   下载/Mbps   延迟/ms"
		start=$(date +%s) 

		 speed_test '30154' '上海' '移动'
		 speed_test '25637' '上海５Ｇ' '移动'
		 speed_test '26728' '云南昆明' '移动'
		 speed_test '27019' '内蒙古呼和浩特' '移动'
		 speed_test '30232' '内蒙呼和浩特５Ｇ' '移动'
		 speed_test '30293' '内蒙古通辽５Ｇ' '移动'
		 speed_test '25858' '北京' '移动'
		 speed_test '16375' '吉林长春' '移动'
		 speed_test '24337' '四川成都' '移动'
		 speed_test '17184' '天津５Ｇ' '移动'
		 speed_test '26940' '宁夏银川' '移动'
		 speed_test '31815' '宁夏银川' '移动'
		 speed_test '26404' '安徽合肥５Ｇ' '移动'
		 speed_test '27151' '山东临沂５Ｇ' '移动'
		 speed_test '25881' '山东济南５Ｇ' '移动'
		 speed_test '27100' '山东青岛５Ｇ' '移动'
		 speed_test '26501' '山西太原５Ｇ' '移动'
		 speed_test '31520' '广东中山' '移动'
		 speed_test '6611' '广东广州' '移动'
		 speed_test '4515' '广东深圳' '移动'
		 speed_test '15863' '广西南宁' '移动'
		 speed_test '16858' '新疆乌鲁木齐' '移动'
		 speed_test '26938' '新疆乌鲁木齐５Ｇ' '移动'
		 speed_test '17227' '新疆和田' '移动'
		 speed_test '17245' '新疆喀什' '移动'
		 speed_test '17222' '新疆阿勒泰' '移动'
		 speed_test '27249' '江苏南京５Ｇ' '移动'
		 speed_test '21845' '江苏常州５Ｇ' '移动'
		 speed_test '32291' '江苏常州５Ｇ' '移动'
		 speed_test '40131' '江苏苏州５Ｇ' '移动'
		 speed_test '26850' '江苏无锡５Ｇ' '移动'
		 speed_test '17320' '江苏镇江５Ｇ' '移动'
		 speed_test '25883' '江西南昌５Ｇ' '移动'
		 speed_test '17223' '河北石家庄' '移动'
		 speed_test '26331' '河南郑州５Ｇ' '移动'
		 speed_test '6715' '浙江宁波５Ｇ' '移动'
		 speed_test '4647' '浙江杭州' '移动'
		 speed_test '16503' '海南海口' '移动'
		 speed_test '28491' '湖南长沙５Ｇ' '移动'
		 speed_test '16145' '甘肃兰州' '移动'
		 speed_test '16171' '福建福州' '移动'
		 speed_test '18444' '西藏拉萨' '移动'
		 speed_test '16398' '贵州贵阳' '移动'
		 speed_test '25728' '辽宁大连' '移动'
		 speed_test '16167' '辽宁沈阳' '移动'
		 speed_test '17584' '重庆' '移动'
		 speed_test '26380' '陕西西安' '移动'
		 speed_test '29105' '陕西西安５Ｇ' '移动'
		 speed_test '29083' '青海西宁５Ｇ' '移动'
		 speed_test '26656' '黑龙江哈尔滨' '移动'

		end=$(date +%s)  
		rm -rf speedtest*
		echo "——————————————————————————————————————————————————————————"
		time=$(( $end - $start ))
		if [[ $time -gt 60 ]]; then
			min=$(expr $time / 60)
			sec=$(expr $time % 60)
			echo -ne "  测试完成, 本次测速耗时: ${min} 分 ${sec} 秒"
		else
			echo -ne "  测试完成, 本次测速耗时: ${time} 秒"
		fi
		echo -ne "\n  当前时间: "
		echo $(TZ=UTC-8 date +%Y-%m-%d" "%H:%M:%S)
	fi
}

runall() {
    selection=2;
	checkroot;
	checksystem;
	checkpython;
	checkspeedtest;
	# clear
	speed_test;
	preinfo;    
	runtest;
	rm -rf speedtest*
}

runall


#############
# 回程测试脚本
#############

echo "回程测试 wget -qO- git.io/besttrace | bash"

#!/bin/bash

# apt -y install unzip

# install besttrace
if [ ! -f "besttrace2021" ]; then
    wget https://github.com/zq/shell/raw/master/besttrace2021
    # unzip besttrace4linux.zip
    chmod +x besttrace2021
fi

## start to use besttrace

next() {
    printf "%-70s\n" "-" | sed 's/\s/-/g'
}

# clear
next

ip_list=(219.141.147.210 202.96.209.133 58.60.188.222 202.106.50.1 210.22.97.1 210.21.196.6 221.179.155.161 211.136.112.200 120.196.165.24 202.112.14.151)
ip_addr=(北京电信 上海电信 深圳电信 北京联通 上海联通 深圳联通 北京移动 上海移动 深圳移动 成都教育网)
# ip_len=${#ip_list[@]}

for i in {0..9}
do
	echo ${ip_addr[$i]}
	./besttrace2021 -q 1 ${ip_list[$i]}
	next
done
# 需要去掉颜色字符，参考 https://stackoverflow.com/questions/17998978/removing-colors-from-output
} | (tee  >(sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGK]//g' > $log))
##############
# 保存文件到 ubuntu pastebin
#############

share_link=$( curl -sF 'clbin=<-' https://clbin.com < $log )
echo " Share result:"
echo " $share_link"
echo ""
rm "geekbench_claim.url"
rm "bench.log"
# 这一部分截取自 https://github.com/sayem314/serverreview-benchmark/blob/master/bench.sh