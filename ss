#! /usr/bin/env bash
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH

#托管：https://github.com/uxh/shadowsocks_bash
#作者：https://www.banwagongzw.com & https://www.vultrcn.com
#致谢：https://teddysun.com

#设置输出颜色
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
plain="\033[0m"

#获取当前目录
currentdir=$(pwd)

#设置加密方式数组
ciphers=(
aes-256-gcm
aes-256-ctr
aes-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

#环境及程序版本控制
libsodiumver="libsodium-1.0.18"
libsodiumurl="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz"
mbedtlsver="mbedtls-2.16.3"
mbedtlsurl="https://tls.mbed.org/download/mbedtls-2.16.3-gpl.tgz"
shadowsocksver="shadowsocks-libev-3.3.3"
shadowsocksurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.3.3/shadowsocks-libev-3.3.3.tar.gz"
initscripturl="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"

#禁用 SElinux
function disable_selinux() {
    if [ -s /etc/selinux/config ] && grep "SELINUX=enforcing" /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#检查当前系统类型
function check_release() {
    local value=$1
    local release="none"

    if [ -f /etc/redhat-release ]; then
        release="centos"
    elif grep -qi "centos|red hat|redhat" /etc/issue; then
        release="centos"
    elif grep -qi "debian|raspbian" /etc/issue; then
        release="debian"
    elif grep -qi "ubuntu" /etc/issue; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /proc/version; then
        release="centos"
    elif grep -qi "debian" /proc/version; then
        release="debian"
    elif grep -qi "ubuntu" /proc/version; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /etc/*-release; then
        release="centos"
    elif grep -qi "debian" /etc/*-release; then
        release="debian"
    elif grep -qi "ubuntu" /etc/*-release; then
        release="ubuntu"
    fi

    if [[ ${value} == ${release} ]]; then
        return 0
    else
        return 1
    fi
}

#检查 Shadowsocks 状态
function check_shadowsocks_status() {
    installedornot="not"
    runningornot="not"
    updateornot="not"
    command -v ss-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installedornot="installed"
        ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            runningornot="running"
        fi
        local installedversion=$(ss-server -h | grep "shadowsocks-libev" | cut -d " " -f 2)
        local latestversion=$(echo "$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep "tag_name" | cut -d "\"" -f 4)" | sed -e 's/^[a-zA-Z]//g')
        if [ ! -z ${latestversion} ]; then
            if [[ ${installedversion} != ${latestversion} ]]; then
                updateornot="update"
                shadowsocksnewver="shadowsocks-libev-${latestversion}"
                shadowsocksnewurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v${latestversion}/${shadowsocksnewver}.tar.gz"
            fi
        fi
    fi
}

#检查 CentOS 系统大版本
function check_centos_main_version() {
    local value=$1
    local version="0.0.0"

    if [ -s /etc/redhat-release ]; then
        version=$(grep -Eo "[0-9.]+" /etc/redhat-release)
    else
        version=$(grep -Eo "[0-9.]+" /etc/issue)
    fi

    local mainversion=${version%%.*}

    if [ ${value} -eq ${mainversion} ]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核一
function check_kernel_version() {
    local kernelversion=$(uname -r | cut -d "-" -f 1)
    local olderversion=$(echo "${kernelversion} 3.7.0" | tr " " "\n" | sort -V | head -n 1)
    if [[ ${olderversion} == "3.7.0" ]]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核二
function check_kernel_headers() {
    local nowkernel=$(uname -r)
    if check_release centos; then
        rpm -qa | grep "headers-${nowkernel}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    else
        dpkg -s linux-headers-${nowkernel} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

#获取系统公网 IPv4
function get_ipv4() {
    local ipv4=$(ip addr | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipv4.icanhazip.com)
    fi
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipinfo.io/ip)
    fi
    echo -e "${ipv4}"
}

#检查系统公网 IPv6
function check_ipv6() {
    local ipv6=$(wget -qO- -t 1 -T 10 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

#设置 Shadowsocks 连接信息
function set_shadowsocks_config() {
    clear
    echo -e "${green}[提示]${plain} 开始配置 Shadowsocks 连接信息"
    echo -e "${green}[提示]${plain} 不清楚的地方，直接回车采用默认配置即可"
    echo ""
    echo "请设置 Shadowsocks 的连接密码"
    #read -p "[默认为 Number1433223]：" sspassword
    if [ -z ${sspassword} ]; then
        sspassword="123"
    fi
    echo "-------------------------------"
    echo "连接密码已设置为：${sspassword}"
    echo "-------------------------------"

    local defaultport="1234"
    echo "请设置 Shadowsocks 连接端口（1~65535）"
    while true
    do
        #read -p "[默认为 ${defaultport}]：" ssport
        #ssport = 1234
        if [ -z ${ssport} ]; then
            ssport=${defaultport}
            echo "连接端口已设置为：${ssport}"
        fi
        expr ${ssport} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ssport} -ge 1 ] && [ ${ssport} -le 65535 ]; then
                echo "-------------------------------"
                echo "连接端口已设置为：${ssport}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
        fi
    done

    echo "请设置 Shadowsocks 的加密方式"
    for ((i=1;i<=${#ciphers[@]};i++));
    do
        local cipher=${ciphers[$i-1]}
        echo -e "${i}) ${cipher}"
    done
    while true
    do
        #read -p "[默认为 ${ciphers[0]}]：" ciphernumber
        #if [ -z ${ciphernumber} ]; then
            ciphernumber="1"
        #fi
        #expr ${ciphernumber} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ciphernumber} -ge 1 ] && [ ${ciphernumber} -le ${#ciphers[@]} ]; then
                sscipher=${ciphers[${ciphernumber}-1]}
                echo "-------------------------------"
                echo "加密方式已设置为：${sscipher}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
        fi
    done

    echo ""
    #echo "按回车键开始安装...或按 Ctrl+C 键取消"
    #read -n 1
}

#安装依赖
function install_dependencies() {
    if check_release centos; then
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release
            if [ $? -ne 0 ]; then
                echo -e "${red}[错误]${plain} EPEL 更新源安装失败，请稍后重试！"
                exit 1
            fi
        fi
        command -v yum-config-manager > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            yum install -y yum-utils
        fi
        local epelstatus=$(yum-config-manager epel | grep -w "enabled" | cut -d " " -f 3)
        if [[ ${epelstatus} != "True" ]]; then
            yum-config-manager --enable epel
        fi
        yum install -y unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    else
        apt-get update
        apt-get install --no-install-recommends -y gettext build-essential autoconf automake libtool openssl libssl-dev zlib1g-dev libpcre3-dev libev-dev libc-ares-dev
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    fi
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
}

#设置防火墙
function set_firewall() {
    if check_release centos; then
        if check_centos_main_version 6; then
            /etc/init.d/iptables status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                iptables -L -n | grep "${ssport}" > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                    /etc/init.d/iptables save
                    /etc/init.d/iptables restart
                fi
            fi
        elif check_centos_main_version 7; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --query-port=${ssport}/tcp > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
                    firewall-cmd --reload
                fi
            fi
        fi
    fi
}

#下载函数
function download() {
    local filename=$1

    if [ -s ${filename} ]; then
        echo -e "${green}[提示]${plain} ${filename} 已下载"
    else
        echo -e "${green}[提示]${plain} ${filename} 未找到，开始下载"
        wget --no-check-certificate -c -t 3 -T 60 -O $1 $2
        if [ $? -eq 0 ]; then
            echo -e "${green}[提示]${plain} ${filename} 下载完成"
        else
            echo -e "${red}[错误]${plain} ${filename} 下载失败，请稍后重试！"
            exit 1
        fi
    fi
}

#安装libsodium
function install_libsodium() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libsodium.a ]; then
        download "${libsodiumver}.tar.gz" "${libsodiumurl}"
        tar zxf ${libsodiumver}.tar.gz
        cd ${libsodiumver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${libsodiumver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${libsodiumver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
}

#安装mbedtls
function install_mbedtls() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        download "${mbedtlsver}-gpl.tgz" "${mbedtlsurl}"
        tar xf ${mbedtlsver}-gpl.tgz
        cd ${mbedtlsver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${mbedtlsver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${mbedtlsver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
}

#创建shadowsocks配置文件
function config_shadowsocks() {
    if check_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    else
        server_value="\"0.0.0.0\""
    fi

    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi

    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":${server_value},
    "server_port":${ssport},
    "password":"${sspassword}",
    "timeout":300,
    "user":"nobody",
    "method":"${sscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

#安装shadowsocks
function install_shadowsocks() {
    ldconfig
    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        download "${shadowsocksver}.tar.gz" "${shadowsocksurl}"
        tar zxf ${shadowsocksver}.tar.gz
        cd ${shadowsocksver}
    else
        download "${shadowsocksnewver}.tar.gz" "${shadowsocksnewurl}"
        tar zxf ${shadowsocksnewver}.tar.gz
        cd ${shadowsocksnewver}
    fi
    ./configure --disable-documentation
    make && make install
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 安装失败，请稍后重试！"
        exit 1
    fi
    if [ ! -f /etc/init.d/shadowsocks ]; then
        download "/etc/init.d/shadowsocks" "${initscripturl}"
    fi
    chmod +x /etc/init.d/shadowsocks
    /etc/init.d/shadowsocks start
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
        exit 1
    fi
    if check_release centos; then
        chkconfig --add shadowsocks
        chkconfig shadowsocks on
    else
        update-rc.d -f shadowsocks defaults
    fi

    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
    else
        rm -rf ${shadowsocksnewver} ${shadowsocksnewver}.tar.gz
    fi
}

#卸载shadowsocks
function uninstall_shadowsocks() {
    ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        /etc/init.d/shadowsocks stop
    fi
    if check_release centos; then
        chkconfig --del shadowsocks
    else
        update-rc.d -f shadowsocks remove
    fi
    rm -rf /etc/shadowsocks-libev
    rm -f /usr/local/bin/ss-local
    rm -f /usr/local/bin/ss-tunnel
    rm -f /usr/local/bin/ss-server
    rm -f /usr/local/bin/ss-manager
    rm -f /usr/local/bin/ss-redir
    rm -f /usr/local/bin/ss-nat
    rm -f /usr/local/lib/libshadowsocks-libev.a
    rm -f /usr/local/lib/libshadowsocks-libev.la
    rm -f /usr/local/include/shadowsocks.h
    rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
    rm -f /usr/local/share/man/man1/ss-local.1
    rm -f /usr/local/share/man/man1/ss-tunnel.1
    rm -f /usr/local/share/man/man1/ss-server.1
    rm -f /usr/local/share/man/man1/ss-manager.1
    rm -f /usr/local/share/man/man1/ss-redir.1
    rm -f /usr/local/share/man/man1/ss-nat.1
    rm -f /usr/local/share/man/man8/shadowsocks-libev.8
    rm -rf /usr/local/share/doc/shadowsocks-libev
    rm -f /etc/init.d/shadowsocks
    rm -f /root/shadowsocks.txt
}

#安装完成信息
function install_success() {
    local ssurl=$(echo -n "${sscipher}:${sspassword}@$(get_ipv4):${ssport}" | base64 -w0)
    clear
    echo -e "${green}[提示]${plain} Shadowsocks 安装成功，配置信息为"
    echo -e "==============================================="
    echo -e "服务器地址  : \033[41;37m $(get_ipv4) \033[0m"
    echo -e "服务端口    : \033[41;37m ${ssport} \033[0m"
    echo -e "连接密码    : \033[41;37m ${sspassword} \033[0m"
    echo -e "加密方式    : \033[41;37m ${sscipher} \033[0m"
    echo -e "-----------------------------------------------"
    echo -e "ss://${ssurl}"
    echo -e "==============================================="

    cat > /root/shadowsocks.txt << EOF
===============================================
服务器地址  : $(get_ipv4)
服务端口    : ${ssport}
连接密码    : ${sspassword}
加密方式    : ${sscipher}
-----------------------------------------------
ss://${ssurl}
===============================================
EOF
    echo -e "配置信息已备份在 /root/shadowsocks.txt 文件内"
    echo -e ""
    echo -e "更多教程请看：https://www.banwagongzw.com & https://www.vultrcn.com"
}

#功能部分一
install_main() {
    disable_selinux
    set_shadowsocks_config
    install_dependencies
    set_firewall
    install_libsodium
    install_mbedtls
    config_shadowsocks
    install_shadowsocks
    install_success
}

#功能部分二
uninstall_main() {
    uninstall_shadowsocks
    echo -e "${green}[提示]${plain} Shadowsocks 已成功卸载"
}

#功能部分三
update_main() {
    if [[ ${updateornot} == "update" ]]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        [ $? -eq 0 ] && /etc/init.d/shadowsocks stop
        install_shadowsocks
        echo -e "${green}[提示]${plain} Shadowsocks 更新成功"
    else
        echo -e "${green}[提示]${plain} Shadowsocks 已安装最新版，无需更新"
    fi
}

#功能部分四
start_main() {
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 启动成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
    fi
}

#功能部分五
stop_main() {
    /etc/init.d/shadowsocks stop
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 停止成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 停止失败，请稍后重试！"
    fi
}

#功能部分六
restart_main() {
    /etc/init.d/shadowsocks stop
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 重启成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 重启失败，请稍后重试！"
    fi
}

#功能部分七
status_main() {
    echo -e "${green}[提示]${plain} 当前 Shadowsocks 配置信息为"
    cat /root/shadowsocks.txt
    echo "此信息仅供参考，具体请查看 Shadowsocks 配置文件"
}

#功能部分八
modify_main() {
    set_shadowsocks_config
    /etc/init.d/shadowsocks stop
    set_firewall
    config_shadowsocks
    /etc/init.d/shadowsocks start
    install_success
    echo ""
    echo "若修改后无法生效，请尝试重启解决！"
}

#起始部分
if [ $EUID -eq 0 ]; then
    if check_release centos || check_release debian || check_release ubuntu; then
        clear
        echo "================================"
        echo " Shadowsocks 一键管理脚本（libev） "
        echo "================================"
        echo " 1. 安装 Shadowsocks 服务        "
        echo " 2. 卸载 Shadowsocks 服务        "
        echo " 3. 更新 Shadowsocks 服务        "
        echo "--------------------------------"
        echo " 4. 启动 Shadowsocks 服务        "
        echo " 5. 停止 Shadowsocks 服务        "
        echo " 6. 重启 Shadowsocks 服务        "
        echo "--------------------------------"
        echo " 7. 查看 Shadowsocks 配置        "
        echo " 8. 修改 Shadowsocks 配置        "
        echo "================================"

        check_shadowsocks_status
        if [[ ${installedornot} == "installed" ]]; then
            if [[ ${runningornot} == "running" ]]; then
                if [[ ${updateornot} == "not" ]]; then
                    echo -e "${green}已安装且正在运行${plain}"
                else
                    echo -e "${green}已安装且正在运行，版本可更新${plain}"
                fi
            else
                echo -e "${yellow}已安装但未运行${plain}"
            fi
        else
            echo -e "${red}尚未安装${plain}"
        fi

        while true
        do
            echo ""
            #read -p "请输入相应功能前面的数字：" choice
            #choice = "1"
            #[[ -z ${choice} ]] && choice="0"
            #expr ${choice} + 1 > /dev/null 2>&1
            #if [ $? -eq 0 ]; then
                #if [ ${choice} -ge 1 ] && [ ${choice} -le 8 ]; then
                    #if [ "${choice}" == "1" ]; then
                        install_main
                   #elif [ "${choice}" == "2" ]; then
                    #    uninstall_main
                   #elif [ "${choice}" == "3" ]; then
                   #     update_main
                   # elif [ "${choice}" == "4" ]; then
                  #      start_main
                   # elif [ "${choice}" == "5" ]; then
                   #     stop_main
                  #  elif [ "${choice}" == "6" ]; then
                  #      restart_main
                  #  elif [ "${choice}" == "7" ]; then
                  #      status_main
                  #  elif [ "${choice}" == "8" ]; then
                  #      modify_main
                  #  fi
                   break
               # else
                #    echo -e "${red}[错误]${plain} 请输入 1 和 8 之间的数字！"
               # fi
          #  else
            #    echo -e "${red}[错误]${plain} 请输入 1 和 8 之间的数字！"
            #fi
        done
    else
        echo -e "${red}[错误]${plain} 本脚本只支持 CentOS、Debian 及 Ubuntu 系统！"
        exit 1
    fi
else
    echo -e "${red}[错误]${plain} 请以 root 用户身份运行此脚本！"
    exit 1
fi





#!/usr/bin/env bash
#
# Auto install latest kernel for TCP BBR
#
# System Required:  CentOS 6+, Debian8+, Ubuntu16+
#
# Copyright (C) 2016-2021 Teddysun <i@teddysun.com>
#
# URL: https://teddysun.com/489.html
#

cur_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_info() {
    _green "[Info] "
    printf -- "%s" "$1"
    printf "\n"
}

_warn() {
    _yellow "[Warning] "
    printf -- "%s" "$1"
    printf "\n"
}

_error() {
    _red "[Error] "
    printf -- "%s" "$1"
    printf "\n"
    exit 1
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

_os() {
    local os=""
    [ -f "/etc/debian_version" ] && source /etc/os-release && os="${ID}" && printf -- "%s" "${os}" && return
    [ -f "/etc/redhat-release" ] && os="centos" && printf -- "%s" "${os}" && return
}

_os_full() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

_os_ver() {
    local main_ver="$( echo $(_os_full) | grep -oE  "[0-9.]+")"
    printf -- "%s" "${main_ver%%.*}"
}

_error_detect() {
    local cmd="$1"
    _info "${cmd}"
    eval ${cmd}
    if [ $? -ne 0 ]; then
        _error "Execution command (${cmd}) failed, please check it and try again."
    fi
}

_is_digit(){
    local input=${1}
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

_is_64bit(){
    if [ $(getconf WORD_BIT) = '32' ] && [ $(getconf LONG_BIT) = '64' ]; then
        return 0
    else
        return 1
    fi
}

_version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

get_valid_valname(){
    local val=${1}
    local new_val=$(eval echo $val | sed 's/[-.]/_/g')
    echo ${new_val}
}

get_hint(){
    local val=${1}
    local new_val=$(get_valid_valname $val)
    eval echo "\$hint_${new_val}"
}

#Display Memu
display_menu(){
    local soft=${1}
    local default=${2}
    eval local arr=(\${${soft}_arr[@]})
    local default_prompt
    if [[ "$default" != "" ]]; then
        if [[ "$default" == "last" ]]; then
            default=${#arr[@]}
        fi
        default_prompt="(default ${arr[$default-1]})"
    fi
    local pick
    local hint
    local vname
    local prompt="which ${soft} you'd select ${default_prompt}: "

    while :
    do
        echo -e "\n------------ ${soft} setting ------------\n"
        for ((i=1;i<=${#arr[@]};i++ )); do
            vname="$(get_valid_valname ${arr[$i-1]})"
            hint="$(get_hint $vname)"
            [[ "$hint" == "" ]] && hint="${arr[$i-1]}"
            echo -e "${green}${i}${plain}) $hint"
        done
        echo
        read -p "${prompt}" pick
        if [[ "$pick" == "" && "$default" != "" ]]; then
            pick=${default}
            break
        fi

        if ! _is_digit "$pick"; then
            prompt="Input error, please input a number"
            continue
        fi

        if [[ "$pick" -lt 1 || "$pick" -gt ${#arr[@]} ]]; then
            prompt="Input error, please input a number between 1 and ${#arr[@]}: "
            continue
        fi

        break
    done

    eval ${soft}=${arr[$pick-1]}
    vname="$(get_valid_valname ${arr[$pick-1]})"
    hint="$(get_hint $vname)"
    [[ "$hint" == "" ]] && hint="${arr[$pick-1]}"
    echo -e "\nyour selection: $hint\n"
}

get_latest_version() {
    latest_version=($(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'\"v' '/v[4-9]./{print $2}' | cut -d/ -f1 | grep -v - | sort -V))
    [ ${#latest_version[@]} -eq 0 ] && _error "Get latest kernel version failed."
    kernel_arr=()
    for i in ${latest_version[@]}; do
        if _version_ge $i 5.9; then
            kernel_arr+=($i);
        fi
    done
    display_menu kernel last
    if _is_64bit; then
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-amd64.deb"
        modules_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-amd64.deb"
    else
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-i386.deb"
        modules_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-i386.deb"
    fi
    [ -z "${deb_name}" ] && _error "Getting Linux kernel binary package name failed, maybe kernel build failed. Please choose other one and try again."
}

get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ x"${param}" == x"bbr" ]]; then
        return 0
    else
        return 1
    fi
}

check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if _version_ge ${kernel_version} 4.9; then
        return 0
    else
        return 1
    fi
}

# Check OS version
check_os() {
    if _exists "virt-what"; then
        virt="$(virt-what)"
    elif _exists "systemd-detect-virt"; then
        virt="$(systemd-detect-virt)"
    fi
    if [ -n "${virt}" -a "${virt}" = "lxc" ]; then
        _error "Virtualization method is LXC, which is not supported."
    fi
    if [ -n "${virt}" -a "${virt}" = "openvz" ] || [ -d "/proc/vz" ]; then
        _error "Virtualization method is OpenVZ, which is not supported."
    fi
    [ -z "$(_os)" ] && _error "Not supported OS"
    case "$(_os)" in
        ubuntu)
            [ -n "$(_os_ver)" -a "$(_os_ver)" -lt 16 ] && _error "Not supported OS, please change to Ubuntu 16+ and try again."
            ;;
        debian)
            [ -n "$(_os_ver)" -a "$(_os_ver)" -lt 8 ] &&  _error "Not supported OS, please change to Debian 8+ and try again."
            ;;
        centos)
            [ -n "$(_os_ver)" -a "$(_os_ver)" -lt 6 ] &&  _error "Not supported OS, please change to CentOS 6+ and try again."
            ;;
        *)
            _error "Not supported OS"
            ;;
    esac
}

sysctl_config() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
}

install_kernel() {
    case "$(_os)" in
        centos)
            if [ -n "$(_os_ver)" ]; then
                if ! _exists "yum-config-manager"; then
                    _error_detect "yum install -y yum-utils"
                fi
                if [ "$(_os_ver)" -eq 6 ]; then
                    _error_detect "rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org"
                    rpm_kernel_url="https://dl.lamp.sh/files/"
                    if _is_64bit; then
                        rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.x86_64.rpm"
                        rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.x86_64.rpm"
                    else
                        rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.i686.rpm"
                        rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.i686.rpm"
                    fi
                    _error_detect "wget -c -t3 -T60 -O ${rpm_kernel_name} ${rpm_kernel_url}${rpm_kernel_name}"
                    _error_detect "wget -c -t3 -T60 -O ${rpm_kernel_devel_name} ${rpm_kernel_url}${rpm_kernel_devel_name}"
                    [ -s "${rpm_kernel_name}" ] && _error_detect "rpm -ivh ${rpm_kernel_name}" || _error "Download ${rpm_kernel_name} failed, please check it."
                    [ -s "${rpm_kernel_devel_name}" ] && _error_detect "rpm -ivh ${rpm_kernel_devel_name}" || _error "Download ${rpm_kernel_devel_name} failed, please check it."
                    rm -f ${rpm_kernel_name} ${rpm_kernel_devel_name}
                    [ ! -f "/boot/grub/grub.conf" ] && _error "/boot/grub/grub.conf not found, please check it."
                    sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
                elif [ "$(_os_ver)" -eq 7 ]; then
                    _error_detect "yum -y install centos-release-xen-48"
                    [ x"$(yum-config-manager centos-virt-xen-48 | grep -w enabled | awk '{print $3}')" != x"True" ] && _error_detect "yum-config-manager --enable centos-virt-xen-48"
                    _error_detect "yum -y update kernel"
                    _error_detect "yum -y install kernel-devel"
                fi
            fi
            ;;
        ubuntu|debian)
            _info "Getting latest kernel version..."
            get_latest_version
            if [ -n "${modules_deb_name}" ]; then
                _error_detect "wget -c -t3 -T60 -O ${deb_kernel_modules_name} ${deb_kernel_modules_url}"
            fi
            _error_detect "wget -c -t3 -T60 -O ${deb_kernel_name} ${deb_kernel_url}"
            _error_detect "dpkg -i ${deb_kernel_modules_name} ${deb_kernel_name}"
            rm -f ${deb_kernel_modules_name} ${deb_kernel_name}
            _error_detect "/usr/sbin/update-grub"
            ;;
        *)
            ;; # do nothing
    esac
}

reboot_os() {
    echo
    _info "The system needs to reboot."
    #read -p "Do you want to restart system? [y/n]" is_reboot
    #is_reboot = "y"
    #if [[ ${is_reboot} == "y" || ${is_reboot} == "Y" ]]; then
        reboot
    #else
    #    _info "Reboot has been canceled..."
    #    exit 0
    #fi
}

install_bbr() {
    if check_bbr_status; then
        echo
        _info "TCP BBR has already been enabled. nothing to do..."
        exit 0
    fi
    if check_kernel_version; then
        echo
        _info "The kernel version is greater than 4.9, directly setting TCP BBR..."
        sysctl_config
        _info "Setting TCP BBR completed..."
        exit 0
    fi
    check_os
    install_kernel
    sysctl_config
    reboot_os
}

[[ $EUID -ne 0 ]] && _error "This script must be run as root"
opsy=$( _os_full )
arch=$( uname -m )
lbit=$( getconf LONG_BIT )
kern=$( uname -r )

clear
echo "---------- System Information ----------"
echo " OS      : $opsy"
echo " Arch    : $arch ($lbit Bit)"
echo " Kernel  : $kern"
echo "----------------------------------------"
echo " Automatically enable TCP BBR script"
echo
echo " URL: https://teddysun.com/489.html"
echo "----------------------------------------"
echo
#echo "Press any key to start...or Press Ctrl+C to cancel"
#char=$(get_char)

install_bbr 2>&1 | tee ${cur_dir}/install_bbr.log
