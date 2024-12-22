#!/usr/bin/env bash
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"
copyright(){
    clear
echo "\
############################################################

Linux Auto 网络优化脚本
Powered by xxx v0.1.0

############################################################
"
}

tcp_tune(){ # 优化TCP窗口
sed -i '/net.ipv4.tcp_no_metrics_save/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_frto/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_rfc1337/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_sack/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fack/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_window_scaling/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_adv_win_scale/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
sed -i '/net.ipv4.udp_rmem_min/d' /etc/sysctl.conf
sed -i '/net.ipv4.udp_wmem_min/d' /etc/sysctl.conf
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p && sysctl --system
}



enable_forwarding(){ #开启内核转发
sed -i '/net.ipv4.conf.all.route_localnet/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.forwarding/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.forwarding/d' /etc/sysctl.conf
cat >> '/etc/sysctl.conf' << EOF
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
EOF
sysctl -p && sysctl --system
}


banping(){
sed -i '/net.ipv4.icmp_echo_ignore_all/d' /etc/sysctl.conf
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
cat >> '/etc/sysctl.conf' << EOF
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
EOF
sysctl -p && sysctl --system
}
unbanping(){
sed -i "s/net.ipv4.icmp_echo_ignore_all=1/net.ipv4.icmp_echo_ignore_all=0/g" /etc/sysctl.conf
sed -i "s/net.ipv4.icmp_echo_ignore_broadcasts=1/net.ipv4.icmp_echo_ignore_broadcasts=0/g" /etc/sysctl.conf
sysctl -p && sysctl --system
}



update(){ # 更新系统 Debian/Ubuntu/Centos
if [ -f /etc/debian_version ]; then
    if [ -f /etc/lsb-release ]; then
        OS="ubuntu"
    else
        OS="debian"
    fi
elif [ -f /etc/redhat-release ]; then
    OS="centos"
else
    echo "无法识别操作系统"
    exit 1
fi

# 根据操作系统类型执行更新命令
case $OS in
    "debian"|"ubuntu")
        echo "正在更新$OS系统..."
        apt update && sudo apt upgrade -y
        ;;
    "centos")
        echo "正在更新CentOS系统..."
        yum update -y && yum upgrade -y
        ;;
esac

echo "系统更新完成！"
}



required() {
    if [[ -f /etc/redhat-release ]]; then
        release="Centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="Debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="Ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="Centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="Debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="Ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="Centos"
    else 
        echo "不支持你当前系统，请使用Ubuntu、Debian或Centos系统"
        rm -f auto.sh
        exit 1
    fi

    if ! type curl >/dev/null 2>&1; then 
        echo "检测到curl未安装，安装中..."
        if [ $release = "Centos" ]; then
            yum -y update && yum install curl -y
        else
            apt-get update -y && apt-get install curl -y
        fi	   
    else
        echo "curl已安装"
    fi

    if ! type wget >/dev/null 2>&1; then 
        echo "检测到wget未安装，安装中..."
        if [ $release = "Centos" ]; then
            yum -y update && yum install wget -y
        else
            apt-get update -y && apt-get install wget -y
        fi	   
    else
        echo "wget已安装"
    fi

    if ! type sudo >/dev/null 2>&1; then 
        echo "检测到sudo未安装，安装中..."
        if [ $release = "Centos" ]; then
            yum -y update && yum install sudo -y
        else
            apt-get update -y && apt-get install sudo -y
        fi	   
    else
        echo "sudo已安装"
    fi

    echo "安装完成！"
}



xrayr(){
wget -N https://raw.githubusercontent.com/XrayR-project/XrayR-release/master/install.sh && bash install.sh && rm install.sh -f
}



blocking(){
wget -N https://cdn.jsdelivr.net/gh/ToyoDAdoubiBackup/doubi@master/ban_iptables.sh && bash ban_iptables.sh && rm ban_iptables.sh -f
}


ssh_port(){ 
wget -N https://cdn.jsdelivr.net/gh/ToyoDAdoubiBackup/doubi@master/ssh_port.sh && bash ssh_port.sh && rm ssh_port.sh -f
}



ssh_hd_passwd() {
    green() {
        echo -e "\033[32m\033[01m$1\033[0m"
    }

    red() {
        echo -e "\033[31m\033[01m$1\033[0m"
    }

    yellow() {
        echo -e "\033[33m\033[01m$1\033[0m"
    }

    sudo lsattr /etc/passwd /etc/shadow >/dev/null 2>&1
    sudo chattr -i /etc/passwd /etc/shadow >/dev/null 2>&1
    sudo chattr -a /etc/passwd /etc/shadow >/dev/null 2>&1
    sudo lsattr /etc/passwd /etc/shadow >/dev/null 2>&1

    green "VPS 允许 root 登录"
    green "VPS enable root login"
    read -p "请输入你的 root 账户密码 (Set your root password):" password
    echo root:$password | sudo chpasswd root
    sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
    sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
    sudo service sshd restart
    green "VPS 用户名: root"
    green "VPS 密码: $password"
    green "VPS username: root"
    green "VPS password: $password"
    yellow "如果出现'sudo:unable to resolve host'的提示可直接忽略"
    yellow "If 'sudo:unable to resolve host' shows, just ignore it"
    echo "Finished!"
}



china(){
cat > /etc/sysctl.conf <<EOF
net.core.rps_sock_flow_entries = 32768 #rfs 设置此文件至同时活跃连接数的最大预期值
fs.file-max = 1024000 # 系统级别的能够打开的文件句柄的数量
fs.inotify.max_user_instances = 65536
#开启路由转发
net.ipv4.conf.all.route_localnet = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
#ARP回应的级别
net.ipv4.neigh.default.gc_stale_time = 60 #ARP缓存的存活时间
net.ipv4.tcp_syncookies = 1 #开启SYN Cookies。当出现SYN等待队列溢出时，启用cookies来处理
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_syn_retries = 2 #SYN重试次数
net.ipv4.tcp_synack_retries = 2 #SYNACK重试次数
net.ipv4.tcp_tw_reuse = 1 #开启TIME-WAIT sockets重用
net.ipv4.tcp_fin_timeout = 15 #保持在FIN-WAIT-2状态的时间
net.ipv4.tcp_max_tw_buckets = 32768 #系统同时保持TIME_WAIT socket的数量
net.core.dev_weight = 4096
net.core.netdev_budget = 65536
net.core.netdev_budget_usecs = 4096
net.ipv4.tcp_max_syn_backlog = 262144 #对于还未获得对方确认的连接请求，可保存在队列中的最大数目
net.core.netdev_max_backlog = 32768 #网口接收数据包比内核处理速率快状态队列的数量
net.core.somaxconn = 32768 #每个端口最大的监听队列的数量
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_keepalive_time = 600 #TCP发送keepalive探测消息的间隔时间（秒）
net.ipv4.tcp_keepalive_probes = 5 #TCP发送keepalive探测确定连接已经断开的次数
net.ipv4.tcp_keepalive_intvl = 15 #探测消息未获得响应时，重发该消息的间隔时间
vm.swappiness = 1
net.ipv4.route.gc_timeout = 100
net.ipv4.neigh.default.gc_thresh1 = 1024 #最小保存条数。当邻居表中的条数小于该数值，则 GC 不会做任何清理
net.ipv4.neigh.default.gc_thresh2 = 4096 #高于该阈值时，GC 会变得更激进，此时存在时间大于 5s 的条目会被清理
net.ipv4.neigh.default.gc_thresh3 = 8192 #允许的最大临时条目数。当使用的网卡数很多，或直连了很多其它机器时考虑增大该参数。
net.ipv6.neigh.default.gc_thresh1 = 1024
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh3 = 8192
net.netfilter.nf_conntrack_max = 262144
net.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 36000 #ESTABLISHED状态连接的超时时间
# TCP窗口
net.ipv4.tcp_fastopen = 3 # 开启TCP快速打开
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_slow_start_after_idle = 0 #关闭TCP的连接传输的慢启动
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_mem = 262144 1048576 4194304
net.ipv4.udp_mem = 262144 524288 1048576
# BBR FQ
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
sysctl -p && sysctl --system
}


tcp(){
wget -O tcp.sh "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh && rm ban_iptables.sh -f
}


ulimit_tune(){

echo "1000000" > /proc/sys/fs/file-max
sed -i '/fs.file-max/d' /etc/sysctl.conf
cat >> '/etc/sysctl.conf' << EOF
fs.file-max=1000000
EOF

ulimit -SHn 1000000 && ulimit -c unlimited
echo "root     soft   nofile    1000000
root     hard   nofile    1000000
root     soft   nproc     1000000
root     hard   nproc     1000000
root     soft   core      1000000
root     hard   core      1000000
root     hard   memlock   unlimited
root     soft   memlock   unlimited

*     soft   nofile    1000000
*     hard   nofile    1000000
*     soft   nproc     1000000
*     hard   nproc     1000000
*     soft   core      1000000
*     hard   core      1000000
*     hard   memlock   unlimited
*     soft   memlock   unlimited
">/etc/security/limits.conf
if grep -q "ulimit" /etc/profile; then
  :
else
  sed -i '/ulimit -SHn/d' /etc/profile
  echo "ulimit -SHn 1000000" >>/etc/profile
fi
if grep -q "pam_limits.so" /etc/pam.d/common-session; then
  :
else
  sed -i '/required pam_limits.so/d' /etc/pam.d/common-session
  echo "session required pam_limits.so" >>/etc/pam.d/common-session
fi

sed -i '/DefaultTimeoutStartSec/d' /etc/systemd/system.conf
sed -i '/DefaultTimeoutStopSec/d' /etc/systemd/system.conf
sed -i '/DefaultRestartSec/d' /etc/systemd/system.conf
sed -i '/DefaultLimitCORE/d' /etc/systemd/system.conf
sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
sed -i '/DefaultLimitNPROC/d' /etc/systemd/system.conf

cat >>'/etc/systemd/system.conf' <<EOF
[Manager]
#DefaultTimeoutStartSec=90s
DefaultTimeoutStopSec=30s
#DefaultRestartSec=100ms
DefaultLimitCORE=infinity
DefaultLimitNOFILE=65535
DefaultLimitNPROC=65535
EOF

systemctl daemon-reload

}



bbr(){

if uname -r|grep -q "^5."
then
    echo "已经是 5.x 内核，不需要更新"
else
    wget -N "http://sh.nekoneko.cloud/bbr/bbr.sh" -O bbr.sh && bash bbr.sh
fi
  
}

Update_Shell(){
  wget -N "http://sh.nekoneko.cloud/tools.sh" -O tools.sh && chmod +x tools.sh && ./tools.sh
}

get_opsy() {
  [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
  [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
  [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}
virt_check() {
  # if hash ifconfig 2>/dev/null; then
  # eth=$(ifconfig)
  # fi

  virtualx=$(dmesg) 2>/dev/null

  if [[ $(which dmidecode) ]]; then
    sys_manu=$(dmidecode -s system-manufacturer) 2>/dev/null
    sys_product=$(dmidecode -s system-product-name) 2>/dev/null
    sys_ver=$(dmidecode -s system-version) 2>/dev/null
  else
    sys_manu=""
    sys_product=""
    sys_ver=""
  fi

  if grep docker /proc/1/cgroup -qa; then
    virtual="Docker"
  elif grep lxc /proc/1/cgroup -qa; then
    virtual="Lxc"
  elif grep -qa container=lxc /proc/1/environ; then
    virtual="Lxc"
  elif [[ -f /proc/user_beancounters ]]; then
    virtual="OpenVZ"
  elif [[ "$virtualx" == *kvm-clock* ]]; then
    virtual="KVM"
  elif [[ "$cname" == *KVM* ]]; then
    virtual="KVM"
  elif [[ "$cname" == *QEMU* ]]; then
    virtual="KVM"
  elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
    virtual="VMware"
  elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
    virtual="Parallels"
  elif [[ "$virtualx" == *VirtualBox* ]]; then
    virtual="VirtualBox"
  elif [[ -e /proc/xen ]]; then
    virtual="Xen"
  elif [[ "$sys_manu" == *"Microsoft Corporation"* ]]; then
    if [[ "$sys_product" == *"Virtual Machine"* ]]; then
      if [[ "$sys_ver" == *"7.0"* || "$sys_ver" == *"Hyper-V" ]]; then
        virtual="Hyper-V"
      else
        virtual="Microsoft Virtual Machine"
      fi
    fi
  else
    virtual="Dedicated母鸡"
  fi
}

get_system_info() {
  cname=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
  #cores=$(awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo)
  #freq=$(awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
  #corescache=$(awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
  #tram=$(free -m | awk '/Mem/ {print $2}')
  #uram=$(free -m | awk '/Mem/ {print $3}')
  #bram=$(free -m | awk '/Mem/ {print $6}')
  #swap=$(free -m | awk '/Swap/ {print $2}')
  #uswap=$(free -m | awk '/Swap/ {print $3}')
  #up=$(awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days %d hour %d min\n",a,b,c)}' /proc/uptime)
  #load=$(w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
  opsy=$(get_opsy)
  arch=$(uname -m)
  #lbit=$(getconf LONG_BIT)
  kern=$(uname -r)
  # disk_size1=$( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $2}' )
  # disk_size2=$( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $3}' )
  # disk_total_size=$( calc_disk ${disk_size1[@]} )
  # disk_used_size=$( calc_disk ${disk_size2[@]} )
  #tcpctrl=$(sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}')
  virt_check
}

menu() {
  echo -e "\
${Green_font_prefix}0.${Font_color_suffix} 升级脚本
${Green_font_prefix}1.${Font_color_suffix} 安装BBR原版内核(已经是5.x的不需要)
${Green_font_prefix}2.${Font_color_suffix} TCP窗口调优
${Green_font_prefix}3.${Font_color_suffix} 开启内核转发
${Green_font_prefix}4.${Font_color_suffix} 系统资源限制调优
${Green_font_prefix}5.${Font_color_suffix} 屏蔽ICMP
${Green_font_prefix}6.${Font_color_suffix} 开放ICMP

${Green_font_prefix}7.${Font_color_suffix} 升级系统
${Green_font_prefix}8.${Font_color_suffix} 安装必备组件
${Green_font_prefix}9.${Font_color_suffix} 安装 Xrayr
${Green_font_prefix}10.${Font_color_suffix} 写入 Host(未完成)
${Green_font_prefix}11.${Font_color_suffix} 屏蔽BT、PT、SMTP
${Green_font_prefix}12.${Font_color_suffix} 修改SSH端口(未完成)
${Green_font_prefix}13.${Font_color_suffix} 开启SSH并修改密码
${Green_font_prefix}14.${Font_color_suffix} 中国linux系统调优
${Green_font_prefix}15.${Font_color_suffix} 外国linux系统调优


${Green_font_prefix}5.${Font_color_suffix} 屏蔽ICMP ${Green_font_prefix}6.${Font_color_suffix} 开放ICMP
"
get_system_info
echo -e "当前系统信息: ${Font_color_suffix}$opsy ${Green_font_prefix}$virtual${Font_color_suffix} $arch ${Green_font_prefix}$kern${Font_color_suffix}
"

  read -p "请输入数字: " num
  case "$num" in
  0)
    Update_Shell
    ;;
  1)
    bbr
    ;;
  2)
    tcp_tune
    ;;
  3)
    enable_forwarding
    ;;
  4)
    ulimit_tune
    ;;
  5)
    banping
    ;;
  6)
    unbanping
    ;;
  7)
    update
    ;;
  8)
    required
    ;;  
  9)
    xrayr
    ;;  
  10)
    Host
    ;; 
  11)
    blocking
    ;; 
  12)
    ssh_port
    ;; 
  13)
    ssh_hd_passwd
    ;; 
  14)
    china
    ;; 
  15)
    tcp
    ;; 
  *)
  clear
    echo -e "${Error}:请输入正确数字 [0-99]"
    sleep 5s
    start_menu
    ;;
  esac
}

copyright

menu
