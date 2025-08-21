#!/bin/bash
HELL=/bin/bash 
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Version: 1.0.0
# Author: Anonymous
# Update: 2025-08-21

# 模块化：yinguard.sh --[option] --[module-option] -f 的方式调用各个模块
# 根据参数执行不同的功能
# 蓝色 [KNOW] 知识点
# 黄色 [INFO] 提示输出
# 黄色 [NOTE] 注意输出
# 红色 [WARN] 警告输出
# 绿色 [SUCC] 成功输出
# 红色 [ERRO] 错误输出
# 白色 原生命令输出


# 大纲输出函数
print_summary() {
	cat << EOF
	检测项目大纲(summary) - v1.0.0
	一.系统信息排查
		- IP地址
		- 系统基础信息
		    - 服务器序列号(SN)检查
		    - CPU使用率实时计算
		    - 硬盘挂载信息检查
		    - 常见软件安装检查(13种软件)
		    - 系统版本详细信息
		    - 系统发行版本
		    - 虚拟化环境检测
		- 用户信息分析
		    - 正在登录用户
		    - 系统最后登录用户
		    - 用户信息passwd文件分析
		    - 检查可登录用户
		    - 检查超级用户(除root外)
		    - 检查克隆用户
		    - 检查非系统用户
		    - 检查空口令用户
		    - 检查空口令且可登录用户
		    - 检查口令未加密用户
		    - 用户组信息group文件分析
		    - 检查特权用户组(除root组外)
		    - 相同GID用户组
		    - 相同用户组名
		- 计划任务分析
		    - 系统计划任务
			- 用户计划任务
		- 历史命令分析
		    - 输出当前shell系统历史命令[history]
		    - 输出用户历史命令[.bash_history]
			- 是否下载过脚本文件
			- 是否通过主机下载,传输过文件
			- 是否增加,删除过账号
			- 是否执行过黑客命令
			- 其他敏感命令
			- 检查系统中所有可能的历史文件路径
			- 输出系统中所有用户的历史文件
			- 输出数据库操作历史命令
	二.网络连接排查
		- ARP 攻击分析
		- 网络连接分析
		- 端口信息排查
		    - TCP 端口检测
			- TCP 高危端口(自定义高危端口组)
		    - UDP 端口检测
			- UDP 高危端口(自定义高危端口组)
		- DNS 信息排查
		- 网卡工作模式
		- 网络路由信息排查
		- 路由转发排查
		- 防火墙策略排查
	三.进程排查
		- ps进程分析
		- top进程分析
		- 规则匹配敏感进程(自定义进程组)
		- 异常进程检测
		- SSH软连接后门检测(-oport=参数)
		- 高级进程隐藏检测
		    - 孤儿进程检测
		    - 网络连接和进程映射
		    - 进程可疑内存映射
		    - 文件描述符异常进程
		    - 系统调用表完整性检测
		    - 进程启动时间异常检测
		    - 进程环境变量异常检测
	四.文件排查
		- 系统服务排查
			- 系统服务收集
			- 系统服务分析
				- 系统自启动服务分析
				- 系统正在运行的服务分析
			- 用户服务分析
		- 敏感目录排查
			- /tmp目录
			- /root目录(隐藏文件)
			- lsof +L1检查(进程存在但文件已删除)
			- 近七天文件ctime检查(系统关键目录)
		- 特殊文件排查
			- ssh相关文件排查
				- .ssh目录排查
				- 公钥私钥排查
				- authorized_keys文件排查
				- known_hosts文件排查
				- sshd_config文件分析
					- 所有开启的配置(不带#号)
					- 检测是否允许空口令登录
					- 检测是否允许root远程登录
					- 检测ssh协议版本
					- 检测ssh版本
			- 环境变量排查
				- 环境变量文件分析
				- env命令分析
				- 正在运行进程的环境变量检查
			- hosts文件排查
			- shadow文件排查
				- shadow文件权限
				- shadow文件属性
				- gshadow文件权限
				- gshadow文件属性
			- 24小时变动文件排查
			- SUID/SGID文件排查
		- 日志文件分析
			- message日志分析
				- ZMODEM传输文件
				- 历史使用DNS情况
			- secure日志分析
				- 登录成功记录分析
				- 登录失败记录分析(SSH爆破)
				- SSH登录成功记录分析
				- 新增用户分析
				- 新增用户组分析
			- 计划任务日志分析(cron)
			    - 定时下载文件
				- 定时执行脚本
			- yum日志分析
			    - yum下载记录
				- yum卸载记录
				- yum安装可疑工具
			- dmesg日志分析[内核自检日志]
			- btmp日志分析[错误登录日志]
			- lastlog日志分析[所有用户最后一次登录日志]
			- wtmp日志分析[所有用户登录日志]
			- journalctl工具日志分析
			   	- 最近24小时日志
			- auditd 服务状态
			- rsyslog 配置文件
	五.统一后门排查
		- 后门进程检测(常见后门程序/反弹shell/隐藏进程)
		- 后门文件检测(可疑路径/隐藏文件/近期修改)
		- 权限提升后门检测(异常SUID/SGID文件)
		- 持久化后门检测(定时任务/系统服务/启动脚本)
		- 网络后门检测(异常监听端口/反向连接)
		- 二进制文件时间戳检测(系统目录/进程文件)
	六.全面隧道检测
		- SSH隧道检测
		    - 同一PID的多个sshd连接
		    - SSH本地转发特征
		    - SSH远程转发特征
		    - SSH动态转发(SOCKS代理)特征
		    - SSH多级跳板特征
		    - SSH隧道网络流量特征
		    - SSH隧道持久化特征
		- HTTP隧道检测
		    - HTTP CONNECT方法检测
		    - HTTP代理进程检测
		    - HTTP隧道工具检测(chisel/frp/ngrok等)
		    - 异常HTTP流量模式分析
		    - 可疑User-Agent检测
		- DNS隧道检测
		    - DNS隧道工具检测(dnscat/iodine等)
		    - DNS查询频率异常分析
		    - 可疑DNS域名模式检测
		    - DNS解析器配置检查
		    - 异常DNS流量检测
		    - DNS缓存分析
		- ICMP隧道检测
		    - ICMP隧道工具检测(icmptunnel/ptunnel等)
		    - 原始套接字使用检测
		    - ping命令异常使用检测
		    - ICMP网络统计分析
		    - 防火墙ICMP规则检查
		    - 系统日志ICMP记录分析
		- 反弹shell检测
		    - 反弹shell进程特征检测
		    - 历史命令反弹shell检测
		    - 网络反向连接检测
		    - 反弹shell工具文件检测
		    - 脚本文件反弹shell代码检测
		    - 环境变量可疑内容检测
	七.WebShell排查
		- 自动Web目录检测
		- PHP WebShell检测(危险函数/常见字符串/编码函数)
		- JSP WebShell检测
		- 图片马检测(隐写术)
		- 一句话木马检测
		- 近期修改/大文件/隐藏文件检测
	八.增强型恶意软件检测
		- 恶意进程检测(35种检测模式)
		    - 挖矿进程检测(知名软件/伪装进程/CPU异常)
		    - 后门进程检测(网络工具/可疑命令)
		    - APT进程检测(持久化/横向移动)
		- 恶意文件检测
		    - 挖矿文件检测(可执行文件/配置文件)
		    - 可疑路径文件检测(/tmp/隐藏文件)
		    - 脚本内容恶意代码检测
		- 网络威胁检测
		    - 挖矿网络行为(矿池连接/域名查询)
		    - DNS威胁检测(可疑域名/异常查询)
		    - 网络异常分析(大量外部连接/异常端口)
		- 持久化威胁检测
		    - 定时任务威胁检测
		    - 系统服务威胁检测
		    - 启动脚本威胁检测
		    - 挖矿配置文件检测
		- 供应链投毒检测
		    - Python包投毒检测(pip/pip3)
		    - Node.js包投毒检测(npm)
		    - Ruby Gem包投毒检测
		    - 系统包管理器投毒检测
	九.内存深度分析
		- 进程内存映射分析
		    - 可读写执行内存区域检测
		    - 已删除文件内存映射检测(内存马特征)
		    - 堆栈异常权限检测
		- 内存马检测
		    - 无文件进程检测(deleted特征)
		    - 进程命令行异常检测
		    - 文件描述符异常检测
		- 异常内存使用分析
		    - 系统内存状况分析
		    - 高内存占用进程分析
		    - 内存碎片化检查
		- 隐藏进程检测
		    - /proc与ps命令差异对比
		    - 内核线程排除算法
		    - 进程详细信息收集
		- 内存字符串分析
		    - 进程环境变量可疑模式检测
		    - 恶意软件特征字符串检测
	十.黑客工具排查
		- 黑客工具匹配(规则自定义)
		- 常见黑客痕迹排查
	十一.内核排查
		- 内核驱动排查
		- 可疑驱动排查(自定义可疑驱动列表)
		- 内核模块检测
	十二.其他排查
		- 可疑脚本文件排查
		- 系统文件完整性检查(关键命令/文件修改时间/类型)
		- 安全风险/漏洞检查
		    - Redis弱密码检测
		    - JDWP调试端口检测  
		    - Python http.server检测
		    - MySQL/SSH/FTP安全配置检查
		- 安装软件排查
	十三.容器安全检查
		- 容器环境检测
		- 容器权限检查(capabilities)
		- 容器挂载检查(敏感目录)
		- 容器进程检查
		- 容器网络检查
	十四.Kubernetes排查
		- 集群信息排查
		- 集群凭据排查
		- 集群敏感文件扫描
		- 集群基线检查
	十五.系统性能分析
		- 磁盘使用情况
		- CPU使用情况
		- 内存使用情况
		- 系统负载情况
		- 网络流量情况
	十六.基线检查
		- 1.账户管理
		    - 1.1 账户审查(用户和组策略) 
		    	- 系统最后登录用户
				- 用户信息passwd文件分析
				- 检查可登录用户
				- 检查超级用户(除root外)
				- 检查克隆用户
				- 检查非系统用户
				- 检查空口令用户
				- 检查空口令且可登录用户
				- 检查口令未加密用户
				- 用户组信息group文件分析
				- 检查特权用户组(除root组外)
				- 相同GID用户组
				- 相同用户组名
			- 1.2 密码策略
		    	- 密码有效期策略
					- 口令生存周期
					- 口令更改最小时间间隔
					- 口令最小长度
					- 口令过期时间天数
				- 密码复杂度策略
				- 密码已过期用户
				- 账号超时锁定策略
				- grub2密码策略检查
				- grub密码策略检查(存在版本久远-弃用)
				- lilo密码策略检查(存在版本久远-弃用)
			- 1.3 远程登录限制
		    	- 远程访问策略(基于 TCP Wrappers)
			    	- 远程允许策略
					- 远程拒绝策略
			- 1.4 认证与授权
				- SSH安全增强
					- sshd配置
					- 空口令登录
					- root远程登录
					- ssh协议版本
				- PAM策略
				- 其他认证服务策略
		- 2.文件权限及访问控制
			- 关键文件保护(文件或目录的权限及属性)
				- 文件权限策略
					- etc文件权限
					- shadow文件权限
					- passwd文件权限
					- group文件权限
					- securetty文件权限
					- services文件权限
					- grub.conf文件权限
					- xinetd.conf文件权限
					- lilo.conf文件权限(存在版本久远-弃用)
					- limits.conf文件权限
					    - core dump 关闭
				- 系统文件属性检查
					- passwd文件属性
					- shadow文件属性
					- gshadow文件属性
					- group文件属性
				- useradd 和 usedel 的时间属性
		- 3.网络配置与服务
			- 端口和服务审计
			- 防火墙配置
				- 允许服务IP端口
			- 网络参数优化
		- 4.selinux策略
		- 5.服务配置策略
			- NIS配置策略
			- SNMP配置检查
			- Nginx配置策略
		- 6.日志记录与监控
			- rsyslog服务
				- 服务开启
				- 文件权限默认
			- audit服务
			- 日志轮转和监控
			- 实时监控和告警
		- 7.备份和恢复策略
		- 8.其他安全配置基准
	十七.企业级功能
		- 远程批量检测
		    - SSH并发扫描(支持密钥/密码认证)
		    - 灵活配置管理(端口/超时/模块选择)
		    - HTML摘要报告生成
		    - 配置模板自动生成
		- 攻击面信息收集
		    - 敏感文件自动收集
		    - 攻击向量分析
		    - 风险评估报告
		- HTML报告生成
		    - 响应式Web界面
		    - 详细检测结果展示
		    - 系统信息汇总
EOF
}
# ------------------------
# 基础变量定义
# 输出颜色定义
typeset RED='\033[0;31m'
typeset BLUE='\033[0;34m'
typeset YELLOW='\033[0;33m'
typeset GREEN='\033[0;32m'
typeset NC='\033[0m'

# 日志级别定义
typeset LOG_DEBUG=0
typeset LOG_INFO=1
typeset LOG_WARN=2
typeset LOG_ERROR=3

# 当前日志级别（默认为INFO）
LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}

# 执行状态跟踪数组（防止重复执行）
# 使用普通变量模拟关联数组,兼容更多shell版本
# executed_functions_userInfoCheck=0
# executed_functions_sshFileCheck=0

# 统一错误处理函数
# 使用方式: handle_error 1 "清理旧k8s目录失败" "init_env"
handle_error() {
	# 使用方式: handle_error 1 "清理旧k8s目录失败" "init_env"
    local error_code=$1		# 自定义错误码 1 一般错误,继续执行 2 严重错误,退出脚本
    local error_msg="$2"	# 错误信息
    local context="$3"		# 错误上下文,用来标注函数位置
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 记录错误日志
    log_message "ERROR" "[$context] $error_msg (错误代码: $error_code)" "$timestamp"
    
    # 根据错误代码决定是否退出
    case $error_code in
        1) # 一般错误,继续执行
            return 1
            ;;
        2) # 严重错误,退出脚本
            echo -e "${RED}[FATAL] 严重错误: $error_msg${NC}"
            exit $error_code
            ;;
        *) # 其他错误
            echo -e "${RED}[ERROR] $error_msg${NC}"
            return $error_code
            ;;
    esac
}

# 分级日志系统
# 使用方式: log_message <level>(DEBUG|INFO|WARN|ERROR) <message> [timestamp](不提提供默认生成时间戳) message.log
log_message() {
    local level="$1"		# 日志等级
    local message="$2"		# 日志消息
    local timestamp="$3"	# 时间戳
    
    # 如果没有提供时间戳,生成一个
    if [ -z "$timestamp" ]; then
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    fi
    
    # 确定日志级别数值
    local level_num
    case "$level" in
        "DEBUG") level_num=$LOG_DEBUG ;;
        "INFO")  level_num=$LOG_INFO ;;
        "WARN")  level_num=$LOG_WARN ;;
        "ERROR") level_num=$LOG_ERROR ;;
        *) level_num=$LOG_INFO ;;
    esac
    
    # 只有当消息级别大于等于当前日志级别时才输出
    if [ $level_num -ge $LOG_LEVEL ]; then
        # 根据级别选择颜色
        local color
        case "$level" in
            "DEBUG") color="$GREEN" ;;   # 绿色
            "INFO")  color="$YELLOW" ;;  # 黄色
            "WARN")  color="$RED" ;;     # 红色
            "ERROR") color="$RED" ;;     # 红色
        esac
        
        # 输出到终端
        echo -e "${color}[$timestamp] [$level] $message${NC}"
        
        # 如果日志文件路径已定义,同时写入日志文件
        if [ -n "$log_file" ] && [ -d "$(dirname "$log_file")" ]; then
			# 格式: [$timestamp] [$level] $message
            echo "[$timestamp] [$level] $message" >> "$log_file/message.log"		# 写入日志-脚本系统日志
        fi
    fi
}

# 操作日志记录函数
# 使用方式: log_operation "功能模块名" "操作描述" "开始|完成(START|END)"  operations.log
log_operation() {
    local operation="$1"	# 操作名称
    local details="$2"		# 操作详情
    local result="$3"		# 操作结果
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local log_entry="[$timestamp] [OPTIN] $operation"
    if [ -n "$details" ]; then
        log_entry="$log_entry - DETAIL: $details"
    fi
    if [ -n "$result" ]; then
        log_entry="$log_entry - RESULT: $result"
    fi
    
    # log_message "INFO" "$log_entry"   # 不再输出到 message.log
	# INFO 输出
    
    # 写入操作日志文件
    if [ -n "$log_file" ] && [ -d "$(dirname "$log_file")" ]; then
        echo "$log_entry" >> "$log_file/operations.log"
    fi
}

# 性能监控日志函数
# 使用方式:  log_performance "函数名称" "开始时间" "结束时间"  performance.log
log_performance() {
    local function_name="$1"	# 函数名称
    local start_time="$2"		# 开始时间
    local end_time="$3"			# 结束时间
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ -n "$start_time" ] && [ -n "$end_time" ]; then
        local duration=$((end_time - start_time))
        # log_message "INFO" "[$timestamp] [PERF] $function_name 执行时间: ${duration}秒"   # 不再输出到 message.log
        
        # 写入性能日志文件
        if [ -n "$log_file" ] && [ -d "$(dirname "$log_file")" ]; then
            echo "[$timestamp] [PERF] $function_name: ${duration}s" >> "$log_file/performance.log"
        fi
    fi
}

# ========== BusyBox 与安全命令封装 ==========
# 目标:
# 1) 优先使用内置(随脚本分发)的 busybox applet,避免系统命令被恶意替换
# 2) 统一封装 ifconfig/netstat/route/ps/top 等,在新系统上用 ip/ss 兼容
# 3) 在非交互模式启用 alias,使脚本内现有调用透明切换

# 启用 alias 展开(在非交互脚本中默认关闭)
shopt -s expand_aliases 2>/dev/null

# 脚本所在目录与 BusyBox 自动发现
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" 2>/dev/null || dirname "$0")" && pwd)"
BB_CANDIDATES=(
    "$BUSYBOX_BIN"
    "$SCRIPT_DIR/busybox"
    "$SCRIPT_DIR/tools/busybox/busybox"
    "/usr/local/bin/busybox"
    "/bin/busybox"
    "/sbin/busybox"
)

BB_BIN=""
for _bb in "${BB_CANDIDATES[@]}"; do
	if [ -n "$_bb" ] && [ -x "$_bb" ]; then
		BB_BIN="$_bb"
		break
	fi
done

# 检查 busybox 是否支持某个 applet
bb_has() {
	[ -n "$BB_BIN" ] && "$BB_BIN" --list | grep -qx "$1"
}

# 优先使用 busybox 的 ip/ps/top/ifconfig/route,并对废弃命令提供兼容层

# 统一的 ip 封装
bb_ip() {
	if bb_has ip; then "$BB_BIN" ip "$@"; else command ip "$@"; fi
}

# 统一的 ps 封装
bb_ps() {
	if bb_has ps; then "$BB_BIN" ps "$@"; else command ps "$@"; fi
}

# 统一的 top 封装
bb_top() {
	if bb_has top; then "$BB_BIN" top "$@"; else command top "$@"; fi
}

# ifconfig 兼容: 优先使用 ip addr; 若无则调用 busybox ifconfig 或系统 ifconfig
bb_ifconfig() {
	if command -v ip >/dev/null 2>&1 || bb_has ip; then
		bb_ip addr "$@"
		return $?
	fi
	if bb_has ifconfig; then "$BB_BIN" ifconfig "$@"; else command ifconfig "$@"; fi
}

# route 兼容: 使用 ip route 替代; 否则退回 busybox/系统 route
bb_route() {
	if command -v ip >/dev/null 2>&1 || bb_has ip; then
		bb_ip route "$@"
		return $?
	fi
	if bb_has route; then "$BB_BIN" route "$@"; else command route "$@"; fi
}

# 将 netstat 常见用法映射为 ss
_bb_ss_from_netstat() {
	# 将 netstat 的部分常用标志转换为 ss 等价参数
	local args="$*"
	local proto_flags=""
	local list_flag=""
	local proc_flag=""
	local numeric_flag="-n"

	# 协议选择
	case "$args" in
		*" -t"*|*" -at"*|*" -ant"*|*" -ntl"*) proto_flags="-t";;
		*" -u"*|*" -au"*|*" -anu"*) proto_flags="-u";;
		*) proto_flags="-t";;
	esac

	# 监听与进程
	case "$args" in
		*" -l"*|*" -nl"*|*" -anl"*) list_flag="-l";;
		*) list_flag="";;
	esac
	case "$args" in
		*" -p"*|*" -ap"*|*" -anp"*) proc_flag="-p";;
		*) proc_flag="";;
	esac

	# 调用 ss
	if command -v ss >/dev/null 2>&1; then
		ss $numeric_flag $list_flag $proto_flags $proc_flag
		return $?
	fi

	# 回退 busybox netstat 或系统 netstat
	if bb_has netstat; then "$BB_BIN" netstat "$@"; else command netstat "$@"; fi
}

bb_netstat() { _bb_ss_from_netstat "$@"; }

# 将别名绑定到封装函数(透明替换现有调用)
alias ip='bb_ip'
alias ps='bb_ps'
alias top='bb_top'
alias ifconfig='bb_ifconfig'
alias route='bb_route'
alias netstat='bb_netstat'

# 基础反篡改自检: 对关键命令进行对比与告警
_bin_path() { command -v "$1" 2>/dev/null || echo "N/A"; }
_self_integrity_check() {
	local warn_list=()
	# 对比 ps/top 的输出来源与是否存在 busybox 备份
	local sys_ps=$(_bin_path ps)
	local sys_top=$(_bin_path top)
	if [ -n "$BB_BIN" ]; then
		# 对比 ps 进程数量差异(阈值 5 行)以提示可疑
		local c1 c2
		c1=$(command ps aux 2>/dev/null | wc -l | tr -d ' ')
		c2=$("$BB_BIN" ps aux 2>/dev/null | wc -l | tr -d ' ')
		if [ -n "$c1" ] && [ -n "$c2" ] && [ "$c1" -lt $((c2-5)) -o "$c1" -gt $((c2+50)) ]; then
			warn_list+=("ps 输出与 busybox ps 差异显著(系统:$c1 / busybox:$c2), 可能被篡改")
		fi
	fi
	for msg in "${warn_list[@]}"; do
		log_message "WARN" "$msg"
	done
}

# 提前执行一次自检(不阻断流程)
_self_integrity_check 2>/dev/null
# ========== BusyBox 与安全命令封装 结束 ==========

# 脚本转换确保可以在Linux下运行
# dos2unix yinguard.sh # 将windows格式的脚本转换为Linux格式 不是必须

# 初始化环境
init_env(){
	local start_time=$(date +%s)	# 获取当前时间戳,用于计算函数耗时
	# 统一函数模块调用的时候添加运行日志输出函数
	log_operation "MOUDLE - INIT_ENV" "开始初始化yinguard运行环境" "START"
	
	# 基础变量定义
	date=$(date +%Y%m%d)
	# 取出本机器上第一个非回环地址的IP地址,用于区分导出的文件
	# 优先使用ip命令,如果不存在则使用ifconfig作为备用
	if command -v ip >/dev/null 2>&1; then
		ipadd=$(ip addr | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}' | sed 's#/\([0-9]\+\)#_\1#') # 192.168.1.1_24
		log_message "INFO" "使用ip命令获取IP地址: $ipadd"
	elif command -v ifconfig >/dev/null 2>&1; then
		ipadd=$(ifconfig | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}' | sed 's#/\([0-9]\+\)#_\1#')
		log_message "INFO" "使用ifconfig命令获取IP地址: $ipadd"
	else
		# 如果都没有,使用主机名作为标识
		ipadd=$(hostname | tr '.' '_')
		log_message "WARN" "未找到ip或ifconfig命令,使用主机名作为标识: $ipadd"
		# WARN 自带黄色警告
	fi
	# 如果ipadd为空,使用默认值
	if [ -z "$ipadd" ]; then
		ipadd="unknown_host"
		log_message "WARN" "无法获取IP地址,使用默认标识: $ipadd"
	fi

	# 创建输出目录变量,当前目录下的output目录
	current_dir=$(pwd)  
	check_file="${current_dir}/output/yinguard_${ipadd}_${date}/check_file"
	log_file="${check_file}/log"
	k8s_file="${check_file}/k8s"
	
	log_message "INFO" "OUTPUT DIR: $check_file"

	# 删除原有的输出目录
	if [ -d "$check_file" ]; then
		rm -rf $check_file && log_message "INFO" "清理旧的输出目录: $check_file" || handle_error 1 "清理旧输出目录失败" "INIT_ENV"
	fi
	if [ -d "$log_file" ]; then
		rm -rf $log_file && log_message "INFO" "清理旧的日志目录: $log_file" || handle_error 1 "清理旧日志目录失败" "INIT_ENV"
	fi
	if [ -d "$k8s_file" ]; then
		rm -rf $k8s_file && log_message "INFO" "清理旧的k8s目录: $k8s_file" || handle_error 1 "清理旧k8s目录失败" "INIT_ENV"
	fi

	# 创建新的输出目录 检查目录 日志目录
	mkdir -p $check_file || handle_error 2 "创建检查目录失败: $check_file" "INIT_ENV"
	mkdir -p $log_file || handle_error 2 "创建日志目录失败: $log_file" "INIT_ENV"
	mkdir -p $k8s_file || handle_error 2 "创建k8s目录失败: $k8s_file" "INIT_ENV"  # 20250702 新增 k8s 检查路径
	
	log_message "INFO" "CREATE DIR SUCCESS"

	# 初始化日志文件
	echo "yinguard v1.0.0 系统日志" > "$log_file/message.log" || handle_error 1 "初始化系统日志文件失败" "INIT_ENV"
	echo "yinguard v1.0.0 操作日志" > "$log_file/operations.log" || handle_error 1 "初始化操作日志文件失败" "INIT_ENV"
	echo "yinguard v1.0.0 性能日志" > "$log_file/performance.log" || handle_error 1 "初始化性能日志文件失败" "INIT_ENV"
	
	# 初始化报告文件
	echo "yinguard v1.0.0 检查项日志输出" > ${check_file}/checkresult.txt || handle_error 2 "初始化检查结果文件失败" "INIT_ENV"
	echo "" >> ${check_file}/checkresult.txt
	# echo "检查发现危险项,请注意:" > ${check_file}/dangerlist.txt
	# echo "" >> ${check_file}/dangerlist.txt

	# 判断目录是否存在
	if [ ! -d "$check_file" ];then
		handle_error 2 "检查目录不存在: ${check_file}" "INIT_ENV"
	fi

	# 进入到检查目录
	cd $check_file || handle_error 2 "无法进入检查目录: $check_file" "INIT_ENV"
	
	local end_time=$(date +%s)
	log_operation "MOUDLE - INIT_ENV" "初始化yinguard运行环境" "END"
	log_performance "INIT_ENV" "$start_time" "$end_time"

}

# 确保当前用户是root用户
ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        # echo -e "${RED}[WARN] 请以 root 权限运行此脚本${NC}"
		log_message "WORN" "请以 root 权限运行此脚本"
        exit 1
    fi
}

################################################################


# 采集系统基础信息【归档 -- systemCheck】
baseInfo(){
    local start_time=$(date +%s)
    log_operation "MOUDLE - BASEINFO" "开始采集系统基础环境信息" "START"
    
    echo -e "${GREEN}==========${YELLOW}1. Get System Info${GREEN}==========${NC}"

    echo -e "${YELLOW}[1.0] 获取IP地址信息:${NC}"
    # 优先使用ip命令,如果不存在则使用ifconfig作为备用
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip addr | grep -w inet | awk '{print $2}') || handle_error 1 "执行ip命令失败" "baseInfo"
        echo -e "${YELLOW}[INFO] 使用ip命令获取IP地址信息:${NC}"
        log_message "INFO" "使用ip命令成功获取IP地址信息"
    elif command -v ifconfig >/dev/null 2>&1; then
        ip=$(ifconfig | grep -w inet | awk '{print $2}') || handle_error 1 "执行ifconfig命令失败" "baseInfo"
        echo -e "${YELLOW}[INFO] 使用ifconfig命令获取IP地址信息:${NC}"
        log_message "INFO" "使用ifconfig命令成功获取IP地址信息"
    else
        ip=""
        echo -e "${RED}[WARN] 系统中未找到ip或ifconfig命令${NC}"
        log_message "ERROR" "系统中未找到ip或ifconfig命令"
    fi
    
    if [ -n "$ip" ]; then
        echo -e "${YELLOW}[INFO] 本机IP地址信息:${NC}" && echo "$ip"
        log_message "INFO" "成功获取IP地址信息: $(echo "$ip" | wc -l)个地址"
    else
        echo -e "${RED}[WARN] 本机未配置IP地址或无法获取IP信息${NC}"
        log_message "WARN" "无法获取IP地址信息"
    fi
    printf "\n"

    echo -e "${YELLOW}[1.1] 系统版本信息[uname -a]:${NC}"
    unameInfo=$(uname -a) || handle_error 1 "执行uname命令失败" "baseInfo"
    if [ -n "$unameInfo" ]; then
        osName=$(echo "$unameInfo" | awk '{print $1}')      # 内核名称
        hostName=$(echo "$unameInfo" | awk '{print $2}')    # 主机名
        kernelVersion=$(echo "$unameInfo" | awk '{print $3}') # 内核版本
        arch=$(echo "$unameInfo" | awk '{print $12}')       # 系统架构
        echo -e "${YELLOW}[INFO] 内核名称: $osName${NC}"
        echo -e "${YELLOW}[INFO] 主机名: $hostName${NC}"
        echo -e "${YELLOW}[INFO] 内核版本: $kernelVersion${NC}"
        echo -e "${YELLOW}[INFO] 系统架构: $arch${NC}"
        log_message "INFO" "系统版本信息: $osName $kernelVersion $arch"
    else
        echo -e "${RED}[WARN] 无法获取系统版本信息${NC}"
        log_message "ERROR" "无法获取系统版本信息"
    fi
    printf "\n"

    echo -e "${YELLOW}[1.2] 系统发行版本信息:${NC}"
    distro="Unknown"
    releaseFile="/etc/os-release"

    if [ -f "$releaseFile" ]; then
        # 推荐使用 os-release 获取标准化信息
        distro=$(grep "^PRETTY_NAME" "$releaseFile" | cut -d= -f2 | tr -d '"')  # CentOS Linux 7 (Core)
        if [ -n "$distro" ]; then
            echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
        else
            echo -e "${RED}[WARN] 未找到有效的系统发行版本信息${NC}"
        fi
    elif [ -f "/etc/redhat-release" ]; then
        distro=$(cat /etc/redhat-release)
        echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
    elif [ -f "/etc/debian_version" ]; then
        debian_ver=$(cat /etc/debian_version)
        distro="Debian GNU/Linux $debian_ver"
        echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
    elif [ -f "/etc/alpine-release" ]; then
        alpine_ver=$(cat /etc/alpine-release)
        distro="Alpine Linux $alpine_ver"
        echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
	elif [ -f "/etc/kylin-release" ]; then  # 麒麟系统
        kylin_ver=$(cat /etc/kylin-release)
        distro="kylin Linux $kylin_ver"
        echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
    elif command -v lsb_release &>/dev/null; then
        distro=$(lsb_release -d | cut -f2)
        echo -e "${YELLOW}[INFO] 系统发行版本: $distro${NC}"
    else
        echo -e "${RED}[WARN] 系统发行版本信息未找到,请手动检查${NC}"
    fi
    printf "\n"

    echo -e "${YELLOW}[1.3] 系统启动时间信息[uptime]:${NC}"
    uptimeInfo=$(uptime)
    if [ -n "$uptimeInfo" ]; then
        echo -e "${YELLOW}[INFO] 系统运行时间信息如下:${NC}"
        echo "$uptimeInfo"
    else
        echo -e "${RED}[WARN] 无法获取系统运行时间信息${NC}"
    fi
    printf "\n"

    echo -e "${YELLOW}[1.4] 系统虚拟化环境检测:${NC}"
    virtWhat=$(dmidecode -s system-manufacturer 2>/dev/null | grep -i virtualbox || true)
    containerCheck=$(grep -E 'container|lxc|docker' /proc/1/environ 2>/dev/null)  #获取 init/systemd 进程的环境变量
	k8swhat=$(grep -E 'POD_NAMESPACE|KUBERNETES_SERVICE_HOST|kubernetes' /proc/1/environ 2>/dev/null)

    if [ -n "$virtWhat" ]; then
        echo -e "${YELLOW}[INFO] 虚拟化环境: VirtualBox${NC}"
        log_message "INFO" "检测到VirtualBox虚拟化环境"
    elif [ -n "$containerCheck" ]; then
        echo -e "${YELLOW}[INFO] 运行在容器[container|lxc|docker]环境中${NC}"
        log_message "INFO" "检测到容器环境: $containerCheck"
	elif [ -n "$k8swhat" ]; then
        echo -e "${YELLOW}[INFO] 运行在 Kubernetes 集群中${NC}"
        log_message "INFO" "检测到Kubernetes集群环境: $k8swhat"
    else
        echo -e "${YELLOW}[INFO] 运行在物理机或未知虚拟化平台${NC}"
        log_message "INFO" "运行在物理机或未知虚拟化平台"
    fi
    printf "\n"
    
    # 记录性能和操作日志
    local end_time=$(date +%s)
    log_performance "baseInfo" "$start_time" "$end_time"
	log_operation "MOUDLE - BASEINFO" "系统基础环境信息采集完成" "END"
}

# 网络信息【完成】
networkInfo(){
    local start_time=$(date +%s)
    log_operation "MOUDLE - NETWORKINFO" "网络信息收集和分析模块" "START"
    
    echo -e "${GREEN}==========${YELLOW}2.Network Info${GREEN}==========${NC}"
    echo -e "${YELLOW}[2.0]Get Network Connection Info${NC}"  
    echo -e "${YELLOW}[2.1]Get ARP Table[arp -a -n]:${NC}"  
    
    log_message "INFO" "开始获取ARP表信息"
    arp=$(arp -a -n 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$arp" ];then
        (echo -e "${YELLOW}[INFO] ARP Table:${NC}" && echo "$arp")  
        log_message "INFO" "成功获取ARP表,共$(echo "$arp" | wc -l)条记录"
    else
        echo -e "${RED}[WARN] 未发现ARP表${NC}"  
        log_message "WARN" "未能获取ARP表信息或ARP表为空"
    fi
    # 原理：通过解析arp表并利用awk逻辑对MAC地址进行计数和识别,然后输出重复的MAC地址以及它们的出现次数
    # 该命令用于统计arp表中的MAC地址出现次数,并显示重复的MAC地址及其出现频率。
    # 具体解释如下：
    # - `arp -a -n`：查询ARP表,并以IP地址和MAC地址的格式显示结果。
    # - `awk '{++S[$4]} END {for(a in S) {if($2>1) print $2,a,S[a]}}'`：使用awk命令进行处理。
    #   - `{++S[$4]}`：对数组S中以第四个字段（即MAC地址）作为索引的元素加1进行计数。
    #   - `END {for(a in S) {if($2>1) print $2,a,S[a]}}`：在处理完所有行之后,遍历数组S。
    #     - `for(a in S)`：遍历数组S中的每个元素。
    #     - `if($2>1)`：如果第二个字段（即计数）大于1,则表示这是一个重复的MAC地址。
    #     - `print $2,a,S[a]`：打印重复的MAC地址的计数、MAC地址本身和出现的次数。

    # ARP攻击检查
    echo -e "${YELLOW}[2.2]Check ARP Attack[arp -a -n]:${NC}"  
    echo -e "${BLUE}[KNOW]:通过解析arp表并利用awk逻辑对MAC地址进行计数和识别,然后输出重复的MAC地址以及它们的出现次数${NC}"  
    
    log_message "INFO" "开始ARP攻击检测"
    arpattack=$(arp -a -n 2>/dev/null | awk '{++S[$4]} END {for(a in S) {if(S[a]>1) print S[a],a}}')
    if [ $? -eq 0 ] && [ -n "$arpattack" ];then
        (echo -e "${RED}[WARN] 发现存在ARP攻击:${NC}" && echo "$arpattack") 
        log_message "WARN" "检测到可能的ARP攻击"
    else
        echo -e "${GREEN}[SUCC] 未发现ARP攻击${NC}"  
        log_message "INFO" "未发现ARP攻击"
    fi

    # 网络连接信息
    echo -e "${YELLOW}[2.3]Get Network Connection Info${NC}"  
    echo -e "${YELLOW}[2.3.1]Check Network Connection[netstat -anlp]:${NC}"  
    
    log_message "INFO" "开始检查网络连接状态"
    netstat=$(netstat -anlp 2>/dev/null | grep ESTABLISHED) # 过滤出已经建立的连接 ESTABLISHED
    if [ $? -ne 0 ]; then
        handle_error 1 "netstat命令执行失败" "networkInfo"
    fi
    
    netstatnum=$(netstat -n 2>/dev/null | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
    if [ -n "$netstat" ];then
        (echo -e "${YELLOW}[INFO] Established Network Connection:${NC}" && echo "$netstat")  
        log_message "INFO" "发现$(echo "$netstat" | wc -l)个已建立的网络连接"
        if [ -n "$netstatnum" ];then
            (echo -e "${YELLOW}[INFO] Number of each state:${NC}" && echo "$netstatnum")  
            log_message "INFO" "网络连接状态统计完成"
        fi
    else
        echo -e "${GREEN}[SUCC] No network connection${NC}"  
        log_message "INFO" "未发现已建立的网络连接"
    fi

    # 端口信息
    ## 检测 TCP 端口
    echo -e "${YELLOW}[2.3.2]Check Port Info[netstat -anlp]:${NC}"  
    echo -e "${BLUE}[KNOW] TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放${NC}"  
    echo -e "${BLUE}[KNOW] 只有绑定在0.0.0.0上局域网才可以访问${NC}"  
    echo -e "${YELLOW}[2.3.2.1]Check TCP Port Info[netstat -anltp]:${NC}"  
    
    log_message "INFO" "开始检查TCP端口信息"
    tcpopen=$(netstat -anltp 2>/dev/null | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
    if [ $? -ne 0 ]; then
        handle_error 1  "TCP端口检查失败" "networkInfo"
    fi
    
    if [ -n "$tcpopen" ];then
        (echo -e "${YELLOW}[INFO] Open TCP ports and corresponding services:${NC}" && echo "$tcpopen")  
        log_message "INFO" "发现$(echo "$tcpopen" | wc -l)个开放的TCP端口"
    else
        echo -e "${GREEN}[SUCC] No open TCP ports${NC}"  
        log_message "INFO" "未发现开放的TCP端口"
    fi

    tcpAccessPort=$(netstat -anltp 2>/dev/null | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
    if [ -n "$tcpAccessPort" ];then
        (echo -e "${RED}[WARN] The following TCP ports are open to the local area network or the Internet, please note!${NC}" && echo "$tcpAccessPort")
        log_message "WARN" "发现$(echo "$tcpAccessPort" | wc -l)个对外开放的TCP端口"
    else
        echo -e "${YELLOW}[INFO] The port is not open to the local area network or the Internet${NC}" 
        log_message "INFO" "未发现对外开放的TCP端口"
    fi

    ## 检测 TCP 高危端口
    echo -e "${YELLOW}[2.3.2.2]Check High-risk TCP Port[netstat -antlp]:${NC}"  
    echo -e "${BLUE}[KNOW] Open ports in dangerstcpports.txt file are matched, and if matched, they are high-risk ports${NC}"  
    
    log_message "INFO" "开始TCP高危端口检测"
    declare -A danger_ports  # 创建关联数组以存储危险端口和相关信息
    # 读取文件并填充关联数组
    if [ ! -f "${current_dir}/checkrules/dangerstcpports.txt" ]; then
        handle_error 1 "TCP高危端口规则文件缺失:${current_dir}/checkrules/dangerstcpports.txt不存在" "networkInfo"
        return 1
    fi
    
    while IFS=: read -r port description; do
        danger_ports["$port"]="$description"
    done < "${current_dir}/checkrules/dangerstcpports.txt"
    log_message "INFO" "已加载$(echo "${!danger_ports[@]}" | wc -w)个TCP高危端口规则"
    
    # 获取所有监听中的TCP端口
    listening_TCP_ports=$(netstat -anlpt 2>/dev/null | awk 'NR>1 {print $4}' | cut -d: -f2 | sort -u) # 获取所有监听中的TCP端口
    if [ $? -ne 0 ]; then
        handle_error 1 "获取TCP监听端口失败" "networkInfo"
    fi
    
    tcpCount=0  # 初始化计数器
    # 遍历所有监听端口
    for port in $listening_TCP_ports; do
        # 如果端口在危险端口列表中
        if [[ -n "${danger_ports[$port]}" ]]; then
            # 输出端口及描述
            echo -e "${RED}[WARN] $port,${danger_ports[$port]}${NC}"    
            ((tcpCount++))
        fi
    done

    if [ $tcpCount -eq 0 ]; then
        echo -e "${GREEN}[SUCC] No TCP dangerous ports found${NC}"  
        log_message "INFO" "TCP高危端口检测完成,未发现高危端口"
    else
        echo -e "${RED}[WARN] Total TCP dangerous ports found: $tcpCount ${NC}"    
        echo -e "${RED}[WARN] Please manually associate and confirm the TCP dangerous ports${NC}"    
        log_message "WARN" "发现 ${tcpCount} 个TCP高危端口,需要人工确认"
    fi

    ## 检测 UDP 端口
    echo -e "${YELLOW}[2.3.2.3]Check UDP Port Info[netstat -anlup]:${NC}"  
    
    log_message "INFO" "开始检查UDP端口信息"
    udpopen=$(netstat -anlup 2>/dev/null | awk  '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
    if [ $? -ne 0 ]; then
        handle_error 1 "UDP端口检查失败" "networkInfo"
    fi
    
    if [ -n "$udpopen" ];then
        (echo -e "${YELLOW}[INFO] Open UDP ports and corresponding services:${NC}" && echo "$udpopen")  
        log_message "INFO" "发现$(echo "$udpopen" | wc -l)个开放的UDP端口"
    else
        echo -e "${GREEN}[SUCC] No open UDP ports${NC}"  
        log_message "INFO" "未发现开放的UDP端口"
    fi

    udpAccessPort=$(netstat -anlup 2>/dev/null | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
    # 检查是否有UDP端口
    if [ -n "$udpAccessPort" ]; then
        echo -e "${YELLOW}[INFO] 以下UDP端口面向局域网或互联网开放:${NC}"  
        log_message "WARN" "发现$(echo "$udpAccessPort" | wc -w)个对外开放的UDP端口"
        for port in $udpAccessPort; do
            if nc -z -w1 127.0.0.1 $port </dev/null 2>/dev/null; then
                echo "$port"  
            fi
        done
    else
        echo -e "${GREEN}[SUCC] 未发现在UDP端口面向局域网或互联网开放.${NC}"  
        log_message "INFO" "未发现对外开放的UDP端口"
    fi

    ## 检测 UDP 高危端口
    echo -e "${YELLOW}[2.3.2.4]Check High-risk UDP Port[netstat -anlup]:${NC}"  
    echo -e "${BLUE}[KNOW] Open ports in dangersudpports.txt file are matched, and if matched, they are high-risk ports${NC}"  
    
    log_message "INFO" "开始UDP高危端口检测"
    declare -A danger_udp_ports  # 创建关联数组以存储危险端口和相关信息
    # 读取文件并填充关联数组
    if [ ! -f "${current_dir}/checkrules/dangersudpports.txt" ]; then
        handle_error 1 "UDP高危端口规则文件缺失:${current_dir}/checkrules/dangersudpports.txt不存在" "networkInfo"
        return 1
    fi
    
    while IFS=: read -r port description; do
        danger_udp_ports["$port"]="$description"
    done < "${current_dir}/checkrules/dangersudpports.txt"
    log_message "INFO" "已加载$(echo "${!danger_udp_ports[@]}" | wc -w)个UDP高危端口规则"
    
    # 获取所有监听中的UDP端口
    listening_UDP_ports=$(netstat -anlup 2>/dev/null | awk 'NR>1 {print $4}' | cut -d: -f2 | sort -u) # 获取所有监听中的UDP端口
    if [ $? -ne 0 ]; then
        handle_error 1 "获取UDP监听端口失败" "networkInfo"
    fi
    
    udpCount=0  # 初始化计数器
    # 遍历所有监听端口
    for port in $listening_UDP_ports; do
        # 如果端口在危险端口列表中
        if [[ -n "${danger_udp_ports[$port]}" ]]; then
            # 输出端口及描述
            echo -e "${RED}[WARN] $port,${danger_udp_ports[$port]}${NC}"    
            ((udpCount++))
        fi
    done

    if [ $udpCount -eq 0 ]; then
        echo -e "${YELLOW}[INFO] No UDP dangerous ports found${NC}"  
        log_message "INFO" "UDP高危端口检测完成,未发现高危端口"
    else
        echo -e "${RED}[WARN] Total UDP dangerous ports found: $udpCount ${NC}"    
        echo -e "${RED}[WARN] Please manually associate and confirm the UDP dangerous ports${NC}"    
        log_message "WARN" "发现${udpCount}个UDP高危端口,需要人工确认"
    fi

    # DNS 信息
    echo -e "${YELLOW}[2.3.3]Check DNS Info[/etc/resolv.conf]:${NC}"  
    
    log_message "INFO" "开始检查DNS配置信息"
    if [ ! -f "/etc/resolv.conf" ]; then
        handle_error 1 "DNS配置文件缺失:/etc/resolv.conf不存在" "networkInfo"
    else
        resolv=$(more /etc/resolv.conf 2>/dev/null | grep ^nameserver | awk '{print $NF}')
        if [ -n "$resolv" ];then
            (echo -e "${YELLOW}[INFO] 该服务器使用以下DNS服务器:${NC}" && echo "$resolv")  
            log_message "INFO" "发现$(echo "$resolv" | wc -l)个DNS服务器配置"
        else
            echo -e "${YELLOW}[INFO] 未发现DNS服务器${NC}"  
            log_message "INFO" "未发现DNS服务器配置"
        fi
    fi

    # 网络共享检查
    echo -e "${YELLOW}[2.3.4]Check Network Share Services[NFS/Samba]:${NC}"
    
    log_message "INFO" "开始检查网络共享服务"
    
    # NFS共享检查
    echo -e "${BLUE}[INFO]${NC} 检查NFS网络文件系统共享..."
    if command -v exportfs >/dev/null 2>&1; then
        local nfs_shares=$(exportfs 2>/dev/null)
        if [[ -n "$nfs_shares" ]]; then
            echo -e "${RED}[WARN]${NC} 发现NFS网络共享服务:"
            echo "$nfs_shares" | while IFS= read -r line; do
                echo -e "  ${RED}→${NC} $line"
            done
            log_message "WARN" "发现NFS网络共享: $(echo "$nfs_shares" | wc -l)个共享目录"
        else
            echo -e "${GREEN}[SUCC]${NC} 未发现NFS共享"
            log_message "INFO" "未发现NFS共享"
        fi
    else
        echo -e "${YELLOW}[NOTE]${NC} exportfs命令不可用，跳过NFS检查"
        log_message "INFO" "exportfs命令不可用，跳过NFS检查"
    fi
    
    # Samba共享检查  
    echo -e "${BLUE}[INFO]${NC} 检查Samba文件共享服务..."
    if command -v smbstatus >/dev/null 2>&1; then
        local smb_shares=$(smbstatus -S 2>/dev/null)
        if [[ -n "$smb_shares" ]] && [[ "$smb_shares" != *"No locked files"* ]]; then
            echo -e "${RED}[WARN]${NC} 发现Samba共享服务:"
            echo "$smb_shares" | while IFS= read -r line; do
                [[ -n "$line" ]] && echo -e "  ${RED}→${NC} $line"
            done
            log_message "WARN" "发现Samba共享服务活动"
        else
            echo -e "${GREEN}[SUCC]${NC} 未发现活动的Samba共享"
            log_message "INFO" "未发现活动的Samba共享"
        fi
    else
        echo -e "${YELLOW}[NOTE]${NC} smbstatus命令不可用，跳过Samba检查"
        log_message "INFO" "smbstatus命令不可用，跳过Samba检查"
    fi
    
    # 检查共享相关的开放端口
    echo -e "${BLUE}[INFO]${NC} 检查共享服务相关端口..."
    local share_ports=("111" "2049" "139" "445" "137" "138")  # NFS: 111,2049; SMB: 139,445,137,138
    local found_share_ports=0
    
    for port in "${share_ports[@]}"; do
        if netstat -anlpt 2>/dev/null | grep -q ":$port "; then
            local port_info=$(netstat -anlpt 2>/dev/null | grep ":$port " | head -1)
            echo -e "${YELLOW}[INFO]${NC} 发现共享服务端口: $port"
            echo -e "  ${YELLOW}→${NC} $port_info"
            found_share_ports=$((found_share_ports + 1))
            log_message "INFO" "发现共享服务端口: $port"
        fi
    done
    
    if [[ $found_share_ports -eq 0 ]]; then
        echo -e "${GREEN}[SUCC]${NC} 未发现共享服务相关端口"
        log_message "INFO" "未发现共享服务相关端口"
    else
        echo -e "${YELLOW}[INFO]${NC} 总计发现 $found_share_ports 个共享服务相关端口"
        log_message "INFO" "发现 $found_share_ports 个共享服务相关端口"
    fi
    printf "\n"

    # 网卡模式
    echo -e "${YELLOW}[2.4]Check Network Card Mode[ip addr]:${NC}"  
    
    log_message "INFO" "开始检查网卡模式信息"
    ifconfigmode=$(ip addr 2>/dev/null | grep '<' | awk  '{print "网卡:",$2,"模式:",$3}' | sed 's/<//g' | sed 's/>//g')
    if [ $? -ne 0 ]; then
        handle_error  1 "网卡模式检查失败 ip addr命令执行失败" "networkInfo"
    fi
    
    if [ -n "$ifconfigmode" ];then
        (echo -e "${YELLOW}[INFO] 网卡模式如下:${NC}" && echo "$ifconfigmode")  
        log_message "INFO" "发现$(echo "$ifconfigmode" | wc -l)个网卡接口"
    else
        echo -e "${RED}[WARN] 未发现网卡模式${NC}"  
        log_message "WARN" "未发现网卡模式信息"
    fi

    # 混杂模式
    echo -e "${YELLOW}[2.4.1]Check Promiscuous Mode[ip addr]:${NC}"  
    Promisc=$(ip addr 2>/dev/null | grep -i promisc | awk -F: '{print $2}')
    if [ -n "$Promisc" ];then
        (echo -e "${RED}[WARN] 网卡处于混杂模式:${NC}" && echo "$Promisc") 
        log_message "WARN" "发现网卡处于混杂模式: $Promisc"
    else
        echo -e "${GREEN}[SUCC] 未发现网卡处于混杂模式${NC}"  
        log_message "INFO" "网卡混杂模式检查完成,未发现异常"
    fi

    # 监听模式
    echo -e "${YELLOW}[2.4.2]Check Monitor Mode[ip addr]:${NC}"  
    Monitor=$(ip addr 2>/dev/null | grep -i "mode monitor" | awk -F: '{print $2}')
    if [ -n "$Monitor" ];then
        (echo -e "${RED}[WARN] 网卡处于监听模式:${NC}" && echo "$Monitor")
        log_message "WARN" "发现网卡处于监听模式"
    else
        echo -e "${GREEN}[SUCC] 未发现网卡处于监听模式${NC}"  
        log_message "INFO" "未发现网卡处于监听模式"
    fi

    # 网络路由信息
    echo -e "${YELLOW}[2.5]Get Network Route Info${NC}"  
    echo -e "${YELLOW}[2.5.1]Check Route Table[route -n]:${NC}"  
    
    log_message "INFO" "开始检查路由表信息"
    route=$(route -n 2>/dev/null)
    if [ $? -ne 0 ]; then
        handle_error 1 "路由表检查失败-route命令执行失败" "networkInfo"
    fi
    
    if [ -n "$route" ];then
        (echo -e "${YELLOW}[INFO] 路由表如下:${NC}" && echo "$route")  
        log_message "INFO" "成功获取路由表,共$(echo "$route" | wc -l)条路由记录"
    else
        echo -e "${RED}[WARN] 未发现路由器表${NC}"  
        log_message "WARN" "未发现路由表信息"
    fi

    # 路由转发
    echo -e "${YELLOW}[2.5.2]Check IP Forward[/proc/sys/net/ipv4/ip_forward]:${NC}"  
    
    log_message "INFO" "开始检查IP转发配置"
    if [ ! -f "/proc/sys/net/ipv4/ip_forward" ]; then
        handle_error 1 "IP转发配置文件缺失-文件/proc/sys/net/ipv4/ip_forward不存在" "networkInfo"
    else
        ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)  # 1:开启路由转发 0:未开启路由转发
        # 判断IP转发是否开启
        if [ "$ip_forward" -eq 1 ]; then
            echo -e "${RED}[WARN] 该服务器开启路由转发,请注意!${NC}"    
            log_message "WARN" "检测到IP转发已开启,存在安全风险"
        else
            echo -e "${GREEN}[SUCC] 该服务器未开启路由转发${NC}"  
            log_message "INFO" "IP转发未开启,配置正常"
        fi
    fi

    # 防火墙策略
    echo -e "${YELLOW}[2.6]Get Firewall Policy${NC}"  
    echo -e "${YELLOW}[2.6.1]Check Firewalld Policy[systemctl status firewalld]:${NC}"  
    
    log_message "INFO" "开始检查firewalld防火墙状态"
    firewalledstatus=$(systemctl status firewalld 2>/dev/null | grep "active (running)")
    if [ -n "$firewalledstatus" ];then
        echo -e "${YELLOW}[INFO] 该服务器防火墙已打开${NC}"  
        log_message "INFO" "firewalld防火墙服务正在运行"
        
        firewalledpolicy=$(firewall-cmd --list-all 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$firewalledpolicy" ];then
            (echo -e "${YELLOW}[INFO] 防火墙策略如下${NC}" && echo "$firewalledpolicy")  
            log_message "INFO" "成功获取firewalld防火墙策略"
        else
            echo -e "${RED}[WARN] 防火墙策略未配置,建议配置防火墙策略!${NC}" 
            log_message "WARN" "firewalld防火墙策略未配置或获取失败"
        fi
    else
        echo -e "${RED}[WARN] 防火墙未开启,建议开启防火墙${NC}" 
        log_message "WARN" "firewalld防火墙服务未运行"
    fi

    echo -e "${YELLOW}[2.6.2]Check Iptables Policy[service iptables status]:${NC}"  
    
    log_message "INFO" "开始检查iptables防火墙状态"
    firewalledstatus=$(service iptables status 2>/dev/null | grep "Table" | awk '{print $1}')  # 有"Table:",说明开启,没有说明未开启
    if [ -n "$firewalledstatus" ];then
        echo -e "${YELLOW}[INFO] iptables已打开${NC}"  
        log_message "INFO" "iptables防火墙服务正在运行"
        
        firewalledpolicy=$(iptables -L 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$firewalledpolicy" ];then
            (echo -e "${YELLOW}[INFO] iptables策略如下${NC}" && echo "$firewalledpolicy")  
            log_message "INFO" "成功获取iptables防火墙策略"
        else
            echo -e "${RED}[WARN] iptables策略未配置,建议配置iptables策略!${NC}" 
            log_message "WARN" "iptables防火墙策略未配置或获取失败"
        fi
    else
        echo -e "${RED}[WARN] iptables未开启,建议开启防火墙${NC}" 
        log_message "WARN" "iptables防火墙服务未运行"
    fi
    
    # 记录网络信息收集完成
    local end_time=$(date +%s)
    log_operation "MOUDLE - NETWORKINFO" "网络信息收集和分析模块执行完成" "END"
    log_performance "networkInfo" $start_time $end_time
    printf "\n"  
}

# 系统基础信息检查【新增功能 - 来自LinuxCheck.sh】
systemCheck(){
	local start_time=$(date +%s)
	log_operation "MOUDLE - SYSTEMCHECK" "开始系统基础信息检查" "START"
	
	echo -e "${GREEN}==========${YELLOW}1. System Basic Info Check${GREEN}==========${NC}"
	
	# 【新增】服务器SN检查 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[1.1] 服务器序列号(SN)检查:${NC}"
	log_message "INFO" "开始检查服务器序列号"
	
	if command -v dmidecode >/dev/null 2>&1; then
		local server_sn=$(dmidecode -s system-serial-number 2>/dev/null | grep -v "^#" | head -1)
		if [[ -n "$server_sn" && "$server_sn" != "Not Specified" ]]; then
			echo -e "${GREEN}[INFO] 服务器序列号: $server_sn${NC}"
			log_message "INFO" "服务器序列号: $server_sn" "systemCheck"
		else
			echo -e "${YELLOW}[NOTE] 服务器序列号未指定或无法获取${NC}"
			log_message "INFO" "服务器序列号未指定或无法获取" "systemCheck"
		fi
	else
		echo -e "${YELLOW}[NOTE] dmidecode命令不可用，跳过SN检查${NC}"
		log_message "INFO" "dmidecode命令不可用，跳过SN检查" "systemCheck"
	fi
	printf "\n"
	
	# 【新增】CPU使用率计算 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[1.2] CPU使用率检查:${NC}"
	log_message "INFO" "开始检查CPU使用率"
	
	if command -v top >/dev/null 2>&1; then
		# 使用top命令获取CPU使用率
		local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' 2>/dev/null)
		if [[ -n "$cpu_usage" ]]; then
			echo -e "${GREEN}[INFO] CPU使用率: ${cpu_usage}%${NC}"
			log_message "INFO" "CPU使用率: ${cpu_usage}%" "systemCheck"
			
			# 检查是否高CPU使用率
			local cpu_int=$(echo "$cpu_usage" | cut -d'.' -f1)
			if [[ "$cpu_int" -gt 80 ]]; then
				echo -e "${RED}[WARN] CPU使用率过高: ${cpu_usage}%${NC}"
				log_message "WARN" "CPU使用率过高: ${cpu_usage}%" "systemCheck"
			fi
		else
			# 备用方法：使用vmstat
			if command -v vmstat >/dev/null 2>&1; then
				local cpu_idle=$(vmstat 1 2 | tail -1 | awk '{print $15}')
				if [[ -n "$cpu_idle" ]]; then
					local cpu_used=$((100 - cpu_idle))
					echo -e "${GREEN}[INFO] CPU使用率: ${cpu_used}% (通过vmstat计算)${NC}"
					log_message "INFO" "CPU使用率: ${cpu_used}%" "systemCheck"
				fi
			else
				echo -e "${YELLOW}[NOTE] 无法获取CPU使用率信息${NC}"
				log_message "INFO" "无法获取CPU使用率信息" "systemCheck"
			fi
		fi
	else
		echo -e "${YELLOW}[NOTE] top命令不可用，跳过CPU使用率检查${NC}"
		log_message "INFO" "top命令不可用，跳过CPU使用率检查" "systemCheck"
	fi
	printf "\n"
	
	# 【新增】硬盘挂载信息检查 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[1.3] 硬盘挂载信息检查:${NC}"
	log_message "INFO" "开始检查硬盘挂载信息"
	
	if command -v df >/dev/null 2>&1; then
		echo -e "${GREEN}[INFO] 磁盘使用情况:${NC}"
		df -h | while read -r line; do
			echo -e "${GREEN}[INFO] $line${NC}"
		done
		log_message "INFO" "磁盘使用情况已记录" "systemCheck"
		
		# 检查磁盘使用率超过90%的挂载点
		local high_usage=$(df -h | awk 'NR>1 {gsub(/%/, "", $5); if($5 > 90) print $0}')
		if [[ -n "$high_usage" ]]; then
			echo -e "${RED}[WARN] 发现磁盘使用率超过90%的挂载点:${NC}"
			echo "$high_usage" | while read -r line; do
				echo -e "${RED}[WARN] $line${NC}"
				log_message "WARN" "高磁盘使用率: $line" "systemCheck"
			done
		fi
	else
		echo -e "${YELLOW}[NOTE] df命令不可用，跳过磁盘检查${NC}"
		log_message "INFO" "df命令不可用，跳过磁盘检查" "systemCheck"
	fi
	printf "\n"
	
	# 【新增】常见软件检查 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[1.4] 常见软件安装检查:${NC}"
	log_message "INFO" "开始检查常见软件安装情况"
	
	local common_software=("nginx" "apache2" "httpd" "mysql" "mariadb" "postgresql" "redis" "docker" "python" "java" "php" "node" "git")
	local installed_software=()
	
	for software in "${common_software[@]}"; do
		if command -v "$software" >/dev/null 2>&1; then
			local version=$(command -v "$software" 2>/dev/null && "$software" --version 2>/dev/null | head -1)
			if [[ -z "$version" ]]; then
				version="已安装(版本信息不可用)"
			fi
			echo -e "${GREEN}[INFO] $software: $version${NC}"
			log_message "INFO" "已安装软件: $software - $version" "systemCheck"
			installed_software+=("$software")
		fi
	done
	
	if [[ ${#installed_software[@]} -eq 0 ]]; then
		echo -e "${YELLOW}[NOTE] 未检测到常见软件安装${NC}"
		log_message "INFO" "未检测到常见软件安装" "systemCheck"
	else
		echo -e "${GREEN}[INFO] 检测到 ${#installed_software[@]} 个常见软件: ${installed_software[*]}${NC}"
		log_message "INFO" "检测到常见软件: ${installed_software[*]}" "systemCheck"
	fi
	printf "\n"
	
	# 【新增】系统版本详细信息 (增强现有功能)
	echo -e "${YELLOW}[1.5] 系统版本详细信息:${NC}"
	log_message "INFO" "开始检查系统版本详细信息"
	
	echo -e "${GREEN}[INFO] 主机名: $(hostname)${NC}"
	echo -e "${GREEN}[INFO] 内核版本: $(uname -r)${NC}"
	echo -e "${GREEN}[INFO] 系统架构: $(uname -m)${NC}"
	
	if [[ -f /etc/os-release ]]; then
		echo -e "${GREEN}[INFO] 操作系统信息:${NC}"
		cat /etc/os-release | while read -r line; do
			echo -e "${GREEN}[INFO] $line${NC}"
		done
	fi
	
	echo -e "${GREEN}[INFO] 系统运行时间: $(uptime)${NC}"
	log_message "INFO" "系统版本详细信息已记录" "systemCheck"
	printf "\n"
	
	# 记录性能和操作日志
	local end_time=$(date +%s)
	log_performance "systemCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - SYSTEMCHECK" "系统基础信息检查完成" "END"
}

# 进程信息分析【完成】
processInfo(){
    local start_time=$(date +%s)
    log_operation "MOUDLE - PROCESSINFO" "开始进程信息分析和安全检测" "START"
    
    echo -e "${GREEN}==========${YELLOW}3. Process Info Analysis${GREEN}==========${NC}"
    
    echo -e "${YELLOW}[3.1] 输出所有系统进程[ps -auxww]:${NC}"
    log_message "INFO" "开始获取所有系统进程信息"
    if ps -auxww >/dev/null 2>&1; then
        ps -auxww
        local process_count=$(ps -auxww | wc -l)
        log_message "INFO" "成功获取系统进程信息,共${process_count}个进程"
    else
        handle_error 1 "获取系统进程信息失败" "processInfo"
    fi
    
    echo -e "${YELLOW}[3.2] 检查内存占用top5的进程[ps -aux | sort -nr -k 4 | head -5]:${NC}"
    log_message "INFO" "开始检查内存占用top5进程"
    if ps -aux | sort -nr -k 4 | head -5 >/dev/null 2>&1; then
        ps -aux | sort -nr -k 4 | head -5
        log_message "INFO" "内存占用top5进程检查完成"
    else
        handle_error 1 "内存占用进程检查失败" "processInfo"
    fi
    
    echo -e "${YELLOW}[3.3] 检查内存占用超过20%的进程:${NC}"
    log_message "INFO" "开始检查内存占用超过20%的进程"
    high_mem_processes=$(ps -aux | sort -nr -k 4 | awk '{if($4>=20) print $0}' | head -5)
    if [ -n "$high_mem_processes" ]; then
        echo "$high_mem_processes"
        local high_mem_count=$(echo "$high_mem_processes" | wc -l)
        log_message "WARN" "发现${high_mem_count}个内存占用超过20%的进程"
    else
        echo -e "${GREEN}[SUCC] 未发现内存占用超过20%的进程${NC}"
        log_message "INFO" "未发现内存占用超过20%的进程"
    fi
    
    echo -e "${YELLOW}[3.4] 检查CPU占用top5的进程[ps -aux | sort -nr -k 3 | head -5]:${NC}"
    log_message "INFO" "开始检查CPU占用top5进程"
    if ps -aux | sort -nr -k 3 | head -5 >/dev/null 2>&1; then
        ps -aux | sort -nr -k 3 | head -5
        log_message "INFO" "CPU占用top5进程检查完成"
    else
        handle_error 1 "CPU占用进程检查失败" "processInfo"
    fi
    
    echo -e "${YELLOW}[3.5] 检查CPU占用超过20%的进程:${NC}"
    log_message "INFO" "开始检查CPU占用超过20%的进程"
    high_cpu_processes=$(ps -aux | sort -nr -k 3 | awk '{if($3>=20) print $0}' | head -5)
    if [ -n "$high_cpu_processes" ]; then
        echo "$high_cpu_processes"
        local high_cpu_count=$(echo "$high_cpu_processes" | wc -l)
        log_message "WARN" "发现${high_cpu_count}个CPU占用超过20%的进程"
    else
        echo -e "${GREEN}[SUCC] 未发现CPU占用超过20%的进程${NC}"
        log_message "INFO" "未发现CPU占用超过20%的进程"
    fi
    # 敏感进程匹配[匹配规则]
    echo -e "${YELLOW}[3.6] 根据规则列表 dangerspslist.txt 匹配检查敏感进程:${NC}"
    log_message "INFO" "开始敏感进程检测"
    
    if [ ! -f "${current_dir}/checkrules/dangerspslist.txt" ]; then
        echo -e "${RED}[WARN] 敏感进程规则文件不存在: ${current_dir}/checkrules/dangerspslist.txt${NC}"
        log_message "WARN" "敏感进程规则文件不存在: ${current_dir}/checkrules/dangerspslist.txt"
    else
        danger_ps_list=$(cat ${current_dir}/checkrules/dangerspslist.txt) || handle_error 1 "读取敏感进程规则文件失败" "processInfo"
        ps_output=$(ps -auxww) || handle_error 1 "获取进程列表失败" "processInfo"
        
        local total_dangerous_processes=0
        for psname in $danger_ps_list; do
            filtered_output=$(echo "$ps_output" | awk -v proc="$psname" '
                BEGIN { found = 0 }
                {
                    if ($11 ~ proc) {
                        print;
                        found++;
                    }
                }
                END {
                    if (found > 0) {
                        printf($0)
                        printf("\n'${RED}'[WARN] 发现敏感进程: %s, 进程数量: %d'${NC}'\n", proc, found);
                    }
                }'
            )
            if [ -n "$filtered_output" ]; then
                echo -e "${RED}$filtered_output${NC}"
                local process_count=$(echo "$filtered_output" | grep -c "$psname" || echo "0")
                total_dangerous_processes=$((total_dangerous_processes + process_count))
                log_message "WARN" "发现敏感进程数量: $process_count"
            fi
        done
        
        if [ $total_dangerous_processes -eq 0 ]; then
            echo -e "${GREEN}[SUCC] 未发现敏感进程${NC}"
            log_message "INFO" "未发现敏感进程"
        else
            log_message "WARN" "共发现 ${total_dangerous_processes} 个敏感进程"
        fi
    fi
    printf "\n" 

    # 异常进程检测：如果存在 /proc 目录中有进程文件夹,但是在 ps -aux 命令里没有显示的,就认为可能是异常进程
    echo -e "${YELLOW}[3.7] 正在检查异常进程(存在于/proc但不在ps命令中显示):${NC}"
    log_message "INFO" "开始异常进程检测"
    
    # 获取所有ps命令显示的PID
    ps_pids=$(ps -eo pid --no-headers | tr -d ' ') || handle_error 1 "获取ps进程列表失败" "processInfo"
    # 获取/proc目录中的所有数字目录(进程PID)
    proc_pids=$(ls /proc/ 2>/dev/null | grep '^[0-9]\+$') || handle_error 1 "获取/proc目录进程列表失败" "processInfo"
    
    # 检查异常进程
    anomalous_processes=()  # 用于存储异常进程的数组
    for proc_pid in $proc_pids; do
        # 检查该PID是否在ps命令输出中
        if ! echo "$ps_pids" | grep -q "^${proc_pid}$"; then
            # 验证/proc/PID目录确实存在且可访问
            if [ -d "/proc/$proc_pid" ] && [ -r "/proc/$proc_pid/stat" ]; then
                # 尝试读取进程信息
                if [ -r "/proc/$proc_pid/comm" ]; then
                    proc_name=$(cat "/proc/$proc_pid/comm" 2>/dev/null || echo "unknown")
                else
                    proc_name="unknown"
                fi
                
                if [ -r "/proc/$proc_pid/cmdline" ]; then
                    proc_cmdline=$(cat "/proc/$proc_pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "unknown")
                else
                    proc_cmdline="unknown"
                fi
                
                # 获取进程状态
                if [ -r "/proc/$proc_pid/stat" ]; then
                    proc_stat=$(cat "/proc/$proc_pid/stat" 2>/dev/null | awk '{print $3}' || echo "unknown")
                else
                    proc_stat="unknown"
                fi
                
                # 获取进程启动时间
                if [ -r "/proc/$proc_pid" ]; then
                    proc_start_time=$(stat -c %Y "/proc/$proc_pid" 2>/dev/null || echo "unknown")
                    if [ "$proc_start_time" != "unknown" ]; then
                        proc_start_time=$(date -d @$proc_start_time 2>/dev/null || echo "unknown")
                    fi
                else
                    proc_start_time="unknown"
                fi
                
                anomalous_processes+=("PID:$proc_pid | Name:$proc_name | State:$proc_stat | StartTime:$proc_start_time | Cmdline:$proc_cmdline")
            fi
        fi
    done
    
    # 输出异常进程结果
    if [ ${#anomalous_processes[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#anomalous_processes[@]} 个异常进程(存在于/proc但不在ps中显示):${NC}"
        for anomalous in "${anomalous_processes[@]}"; do
            echo -e "${RED}[WARN] $anomalous${NC}"
        done
        echo -e "${RED}[WARN] 建议进一步调查这些进程,可能存在进程隐藏${NC}"
        log_message "WARN" "发现${#anomalous_processes[@]}个异常进程"
    else
        echo -e "${GREEN}[SUCC] 未发现异常进程,所有/proc中的进程都能在ps命令中找到${NC}"
        log_message "INFO" "未发现异常进程,所有/proc中的进程都能在ps命令中找到"
    fi
    printf "\n"

    # 高级进程隐藏检测技术
    echo -e "${YELLOW}[3.8] 执行高级进程隐藏检测:${NC}"
    log_message "INFO" "开始高级进程隐藏检测"
    
    # 1. 检查进程树完整性
    echo -e "${YELLOW}[3.8.1] 检查进程树完整性(孤儿进程检测):${NC}"
    log_message "INFO" "开始进程树完整性检查"
    orphan_processes=()
    
    ps_tree_output=$(ps -eo pid,ppid 2>/dev/null | tail -n +2) || handle_error 1 "获取进程树信息失败" "processInfo"
    while IFS= read -r line; do
        # 使用更精确的字段提取,处理不同系统的ps输出格式
        pid=$(echo "$line" | awk '{print $1}')
        ppid=$(echo "$line" | awk '{print $2}')
        # 验证PID和PPID都是数字
        if [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$ppid" =~ ^[0-9]+$ ]]; then
            # 检查父进程是否存在(除了init进程和内核线程)
            if [ "$ppid" != "0" ] && [ "$ppid" != "1" ] && [ "$ppid" != "2" ]; then
                if ! ps -p "$ppid" > /dev/null 2>&1; then
                    orphan_processes+=("PID:$pid PPID:$ppid (父进程不存在)")
                fi
            fi
        fi
    done <<< "$ps_tree_output"
    
    if [ ${#orphan_processes[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#orphan_processes[@]} 个可疑孤儿进程:${NC}"
        for orphan in "${orphan_processes[@]}"; do
            echo -e "${RED}[WARN] $orphan${NC}"
        done
        log_message "WARN" "发现${#orphan_processes[@]}个可疑孤儿进程"
    else
        echo -e "${GREEN}[SUCC] 进程树完整性检查通过${NC}"
        log_message "INFO" "进程树完整性检查通过"
    fi
    printf "\n"
	
    # 2. 检查网络连接与进程对应关系
    echo -e "${YELLOW}[3.8.2] 检查网络连接与进程对应关系:${NC}"
    log_message "INFO" "开始检查网络连接与进程对应关系"
    unknown_connections=()
    
    # 检测操作系统类型并使用相应的命令
    if [[ "$(uname)" == "Darwin" ]]; then  # macOS
        # macOS系统使用lsof命令
        if command -v lsof > /dev/null 2>&1; then
            lsof_output=$(lsof -i -n -P 2>/dev/null | tail -n +2) || handle_error 1 "lsof命令执行失败" "processInfo"
            while IFS= read -r line; do
                # lsof输出格式: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                if echo "$line" | grep -E "(TCP|UDP)" > /dev/null; then
                    pid=$(echo "$line" | awk '{print $2}')
                    # 验证PID是数字且检查进程是否存在
                    if [[ "$pid" =~ ^[0-9]+$ ]] && ! ps -p "$pid" > /dev/null 2>&1; then
                        proc_name=$(echo "$line" | awk '{print $1}')
                        unknown_connections+=("连接: $line (进程PID:$pid Name:$proc_name 不存在)")
                    fi
                fi
            done <<< "$lsof_output"
        else
            echo -e "${YELLOW}[INFO] macOS系统未找到lsof命令,跳过网络连接检查${NC}"
            log_message "WARN" "macOS系统未找到lsof命令,跳过网络连接检查"
        fi
    else
        # Linux系统使用netstat或ss命令
        if command -v netstat > /dev/null 2>&1; then
            netstat_output=$(netstat -tulnp 2>/dev/null | grep -v '^Active') || handle_error 1 "netstat命令执行失败" "processInfo"
            while IFS= read -r line; do
                if echo "$line" | grep -q "/"; then
                    pid_info=$(echo "$line" | awk '{print $NF}')
                    pid=$(echo "$pid_info" | cut -d'/' -f1)
                    if [ "$pid" != "-" ] && [[ "$pid" =~ ^[0-9]+$ ]] && ! ps -p "$pid" > /dev/null 2>&1; then
                        unknown_connections+=("连接: $line (进程PID:$pid 不存在)")
                    fi
                fi
            done <<< "$netstat_output"
        else
            # 使用ss命令作为备选
            if command -v ss > /dev/null 2>&1; then
                ss_output=$(ss -tulnp 2>/dev/null) || handle_error 1 "ss命令执行失败" "processInfo"
                while IFS= read -r line; do
                    if echo "$line" | grep -q "pid="; then
                        pid=$(echo "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
                        if [ -n "$pid" ] && [[ "$pid" =~ ^[0-9]+$ ]] && ! ps -p "$pid" > /dev/null 2>&1; then
                            unknown_connections+=("连接: $line (进程PID:$pid 不存在)")
                        fi
                    fi
                done <<< "$ss_output"
            else
                echo -e "${RED}[WARN] Linux系统未找到netstat或ss命令,跳过网络连接检查${NC}"
                log_message "WARN" "Linux系统未找到netstat或ss命令,跳过网络连接检查"
            fi
        fi
    fi
    
    if [ ${#unknown_connections[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#unknown_connections[@]} 个可疑网络连接:${NC}"
        for conn in "${unknown_connections[@]}"; do
            echo -e "${RED}[WARN] $conn${NC}"
        done
        log_message "WARN" "发现${#unknown_connections[@]}个可疑网络连接"
    else
        echo -e "${GREEN}[SUCC] 网络连接与进程对应关系检查通过${NC}"
        log_message "INFO" "网络连接与进程对应关系检查通过"
    fi
    printf "\n"
	
    # 3. 检查进程内存映射异常
    echo -e "${YELLOW}[3.8.3] 检查进程内存映射异常:${NC}"
    log_message "INFO" "开始进程内存映射异常检查"
    suspicious_maps=()  # 存储可疑内存映射
    for proc_dir in /proc/[0-9]*; do
        if [ -d "$proc_dir" ] && [ -r "$proc_dir/maps" ]; then  # 检查进程目录是否存在和maps文件是否可读
            pid=$(basename "$proc_dir")
            # 检查是否有可疑的内存映射(如可执行的匿名映射)
            ## 原理: 通过grep命令匹配maps文件中的rwxp权限的行,并判断是否包含[heap]或[stack]或deleted	
            ## rwxp.*\[heap\]: 堆区域具有读写执行权限(异常|正常堆不应该具有可执行权限,只有 rw-)
            ## rwxp.*\[stack\]: 栈区域具有读写执行权限(异常|正常栈栈不应该具有可执行权限,只有 rw- 可能是栈溢出攻击,或者 shellcode 直接执行机器码)
            ## rwxp.*deleted: 指向已经删除的文件的可执行内存映射(异常|内存马或者恶意代码)
            ## 恶意软件删除自身文件但保持在内存中运行
            ## 无文件攻击的检测 和 rootkit隐藏技术发现

			# 判断进程是否仍然存在
            if ! ps -p "$pid" >/dev/null; then
                handle_error 0 "进程 ${pid} 已不存在" "processInfo"
				continue   # 跳过当前循环
            fi

            # suspicious_map=$(grep -E "(rwxp.*\[heap\]|rwxp.*\[stack\]|rwxp.*deleted)" "$proc_dir/maps" 2>/dev/null) || handle_error 0 "读取进程 ${pid} 内存映射失败" "processInfo"
			# 读取内存映射文件内容（防止多次读取）
			map_content=$(cat "$proc_dir/maps" 2>/dev/null)

			# 判断是否读取失败（如文件不存在、权限不足）
			if [ $? -ne 0 ]; then
				handle_error 0 "读取进程 ${pid} 内存映射失败" "processInfo"
				continue  # 跳过当前进程
			fi

			# 执行 grep 匹配可疑映射（即使没有匹配内容也不报错）
			suspicious_map=$(echo "$map_content" | grep -E "(rwxp.*$$heap$$|rwxp.*$$stack$$|rwxp.*deleted)")

			# 判断是否有匹配内
            if [ -n "$suspicious_map" ]; then   
                proc_name=$(cat "$proc_dir/comm" 2>/dev/null || echo "unknown")
                suspicious_maps+=("PID:$pid Name:$proc_name 可疑内存映射")
            fi
        fi
    done
    
    if [ ${#suspicious_maps[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#suspicious_maps[@]} 个进程存在可疑内存映射:${NC}"
        for map in "${suspicious_maps[@]}"; do
            echo -e "${RED}[WARN] $map${NC}"
        done
        log_message "WARN" "发现${#suspicious_maps[@]}个进程存在可疑内存映射"
    else
        echo -e "${GREEN}[SUCC] 进程内存映射检查通过${NC}"
        log_message "INFO" "进程内存映射检查通过"
    fi
    printf "\n"
	
    # 4. 检查进程文件描述符异常[(deleted)]
    echo -e "${YELLOW}[3.8.4] 检查进程文件描述符异常[(deleted)]:${NC}"
    log_message "INFO" "开始进程文件描述符异常检查"
    suspicious_fds=()  # 用于存储异常文件描述符的数组
    for proc_dir in /proc/[0-9]*; do
        if [ -d "$proc_dir/fd" ] && [ -r "$proc_dir/fd" ]; then
            pid=$(basename "$proc_dir")
            # 检查是否有指向已删除文件的文件描述符
            deleted_files=$(ls -l "$proc_dir/fd/" 2>/dev/null | grep "(deleted)" | wc -l) || handle_error 0 "读取进程 ${pid} 文件描述符失败" "processInfo"
            if [ "$deleted_files" -gt 0 ]; then
                proc_name=$(cat "$proc_dir/comm" 2>/dev/null || echo "unknown")
                suspicious_fds+=("PID:$pid Name:$proc_name 有${deleted_files}个已删除文件的文件描述符")
                # 输出fd是(deleted)的进程pid和进程名
                # 检测恶意进程删除自身进程然后在内存里驻留
            fi
        fi
    done
    
    if [ ${#suspicious_fds[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#suspicious_fds[@]} 个进程存在可疑文件描述符[(deleted)]:${NC}"
        for fd in "${suspicious_fds[@]}"; do
            echo -e "${RED}[WARN] $fd${NC}"
        done
        log_message "WARN" "发现${#suspicious_fds[@]}个进程存在可疑文件描述符"
    else
        echo -e "${GREEN}[SUCC] 进程文件描述符检查通过${NC}"
        log_message "INFO" "进程文件描述符检查通过"
    fi
    printf "\n"
	
    # 5. 检查系统调用表完整性(需要root权限)
    echo -e "${YELLOW}[3.8.5] 检查系统调用表完整性[sys_call_table(/proc/kallsyms)]:${NC}"
    log_message "INFO" "开始系统调用表完整性检查"
    ## 原理: 通过查看系统调用表,判断系统调用表是否被修改[rootkit检测和内核级模块检测常用的技术]
    # 什么是系统调用表（sys_call_table）
    # - 定义 ：Linux内核中存储所有系统调用函数指针的数组
    # - 作用 ：当用户程序调用系统调用时,内核通过这个表找到对应的处理函数
    # - 位置 ：位于内核内存空间,通过 /proc/kallsyms 可以查看其地址 
    # 检测系统表的意义：
    # 1. Rootkit检测
    # 系统调用表劫持 是rootkit的常用技术：
    # - 正常情况 ： sys_call_table 符号在 /proc/kallsyms 中可见
    # - 被攻击 ：rootkit可能隐藏或修改这个符号来逃避检测 
    # 2. 内核级恶意模块检测
    # 通过搜索可疑符号名称,可以发现：
    # - 恶意内核模块 ：包含 "rootkit"、"hide" 等字样的符号
    # - Hook技术 ：用于拦截和修改系统调用的钩子函数
    # - 隐蔽功能 ：用于隐藏进程、文件、网络连接的功能
    if [ "$(id -u)" -eq 0 ]; then
        if [ -r "/proc/kallsyms" ]; then
            # 检查sys_call_table符号是否存在
            sys_call_table=$(grep "sys_call_table" /proc/kallsyms 2>/dev/null) || handle_error 0 "读取/proc/kallsyms失败" "processInfo"
            if [ -n "$sys_call_table" ]; then
                echo -e "${YELLOW}[INFO] 系统调用表符号存在: $sys_call_table ${NC}"
                log_message "INFO" "系统调用表符号存在"
            else
                echo -e "${RED}[WARN] 警告: 无法找到sys_call_table符号,可能被隐藏${NC}"
                log_message "WARN" "无法找到sys_call_table符号,可能被隐藏"
            fi
            
            # 检查可疑的内核符号[过滤可能恶意的符号(自定义)]
            suspicious_symbols=$(grep -E "(hide|rootkit|stealth|hook)" /proc/kallsyms 2>/dev/null) || handle_error 0 "搜索可疑内核符号失败" "processInfo"
            if [ -n "$suspicious_symbols" ]; then
                echo -e "${RED}[WARN] 发现可疑内核符号:${NC}"
                echo "$suspicious_symbols"
                log_message "WARN" "发现可疑内核符号"
            else
                echo -e "${GREEN}[SUCC] 未发现可疑内核符号${NC}"
                log_message "INFO" "未发现可疑内核符号"
            fi
        else
            echo -e "${YELLOW}[INFO] /proc/kallsyms不可读,跳过系统调用表检查${NC}"
            log_message "WARN" "/proc/kallsyms不可读,跳过系统调用表检查"
        fi
    else
        echo -e "${RED}[WARN] 需要root权限进行系统调用表检查${NC}"
        log_message "WARN" "需要root权限进行系统调用表检查"
    fi
    printf "\n"
	
    # 6. 检查进程启动时间异常
    echo -e "${YELLOW}[3.8.6] 检查进程启动时间异常:${NC}"
    log_message "INFO" "开始进程启动时间异常检查"
    time_anomalies=()
    current_time=$(date +%s) || handle_error 1 "获取当前时间失败" "processInfo"
    ps_output=$(ps -eo pid,lstart --no-headers 2>/dev/null) || handle_error 1 "获取进程启动时间失败" "processInfo"
    while IFS= read -r line; do
        pid=$(echo "$line" | awk '{print $1}')
        start_time=$(echo "$line" | awk '{print $2}')
        # 检查启动时间是否在未来(可能的时间篡改)
        if [ "$start_time" -gt "$current_time" ]; then
            proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            time_anomalies+=("PID:$pid Name:$proc_name 启动时间异常(未来时间)")
        fi
    done <<< "$(echo "$ps_output" | while read -r pid lstart_str; do echo "$pid $(date -d \"$lstart_str\" +%s 2>/dev/null || echo 0)"; done)"
    
    if [ ${#time_anomalies[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#time_anomalies[@]} 个进程启动时间异常:${NC}"
        for anomaly in "${time_anomalies[@]}"; do
            echo -e "${RED}[WARN] $anomaly${NC}"
        done
        log_message "WARN" "发现${#time_anomalies[@]}个进程启动时间异常"
    else
        echo -e "${GREEN}[SUCC] 进程启动时间检查通过${NC}"
        log_message "INFO" "进程启动时间检查通过"
    fi
    printf "\n"
	
    # 7. 检查进程环境变量异常
    # 这段代码通过以下机制检测潜在威胁：
    # 1. LD_PRELOAD检测 ：这是最常见的rootkit技术,通过预加载恶意库来劫持系统调用
    # 2. 动态库路径检测 ：异常的LD_LIBRARY_PATH设置可能指向恶意库
    # 3. 明显恶意标识 ：直接搜索ROOTKIT、HIDE等明显的恶意软件标识
    echo -e "${YELLOW}[3.8.7] 检查进程环境变量异常:${NC}"
    log_message "INFO" "开始进程环境变量异常检查"
	env_anomalies=()
    for proc_dir in /proc/[0-9]*; do
        if [ -r "$proc_dir/environ" ]; then
            pid=$(basename "$proc_dir")

			# 判断进程是否仍然存在
            if ! ps -p "$pid" >/dev/null; then
                handle_error 0 "进程 ${pid} 已不存在" "processInfo"
				continue   # 跳过当前循环
            fi

            # 检查可疑的环境变量 读取 environ 文件
            # suspicious_env=$(tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null | grep -E "(LD_PRELOAD|LD_LIBRARY_PATH.*\.so|ROOTKIT|HIDE)" 2>/dev/null) || handle_error 0 "读取进程 ${pid} 环境变量失败" "processInfo"

			# 先读取环境变量内容并转换为换行分隔
			env_content=$(tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null)

			# 判断 tr 是否失败（比如文件不存在、权限问题）
			if [ $? -ne 0 ]; then
				handle_error 0 "读取进程 ${pid} 环境变量失败" "processInfo"
				continue   # 跳过当前循环
			fi

			# 然后执行 grep，不管有没有匹配内容，都不触发错误
			suspicious_env=$(echo "$env_content" | grep -E "(LD_PRELOAD|LD_LIBRARY_PATH.*\.so|ROOTKIT|HIDE)")

			# 判断是否有匹配内容
			if [ -n "$suspicious_env" ]; then
                proc_name=$(cat "$proc_dir/comm" 2>/dev/null || echo "unknown")
                env_anomalies+=("PID:$pid Name:$proc_name 可疑环境变量: $(echo \"$suspicious_env\" | head -1)")
            fi
        fi
    done

    if [ ${#env_anomalies[@]} -gt 0 ]; then
        echo -e "${RED}[WARN] 发现 ${#env_anomalies[@]} 个进程存在可疑环境变量:${NC}"
        for env in "${env_anomalies[@]}"; do
            echo -e "${RED}[WARN] $env${NC}"
        done
        log_message "WARN" "发现${#env_anomalies[@]}个进程存在可疑环境变量"
    else
        echo -e "${GREEN}[SUCC] 进程环境变量检查通过${NC}"
        log_message "INFO" "进程环境变量检查通过"
    fi
    printf "\n"
    
    # 【新增】SSH软连接后门检测 (来自LinuxCheck.sh)
    echo -e "${YELLOW}[3.8] SSH软连接后门检测:${NC}"
    log_message "INFO" "开始SSH软连接后门检测"
    
    local ssh_backdoor_processes=$(ps -ef | grep -P '\s+\-oport=\d+' | grep -v 'grep' 2>/dev/null)
    if [[ -n "$ssh_backdoor_processes" ]]; then
        echo -e "${RED}[WARN] 发现SSH软连接后门进程:${NC}"
        echo "$ssh_backdoor_processes" | while read -r line; do
            echo -e "${RED}[WARN] $line${NC}"
            log_message "WARN" "SSH软连接后门进程: $line" "processInfo"
        done
    else
        echo -e "${GREEN}[SUCC] 未检测到SSH软连接后门${NC}"
        log_message "INFO" "未检测到SSH软连接后门"
    fi
    printf "\n"
    
    # 记录性能和操作日志
    local end_time=$(date +%s)
    log_performance "processInfo" "$start_time" "$end_time"
    log_operation "MOUDLE - PROCESSINFO" "进程信息分析和安全检测完成" "END"
}

# 计划任务排查【归档 -- systemCheck】
crontabCheck(){
    local start_time=$(date +%s)
    log_operation "MOUDLE - CRONTABCHECK" "计划任务分析和安全检测" "START"
    
    echo -e "${GREEN}==========${YELLOW}Crontab Analysis${GREEN}==========${NC}"
    
    # 系统计划任务收集
    echo -e "${YELLOW}[INFO] 输出系统计划任务[/etc/crontab | /etc/cron*/* ]:${NC}" 
    log_message "INFO" "开始收集系统计划任务信息"
    
    # 检查系统计划任务文件
    echo -e "${YELLOW}[INFO] 系统计划任务[/etc/crontab]:${NC}"
    if [ -f "/etc/crontab" ]; then
        if cat /etc/crontab | grep -v "^$" >/dev/null 2>&1; then
            cat /etc/crontab | grep -v "^$"  # 去除空行
            log_message "INFO" "成功读取/etc/crontab文件"
        else
            handle_error 1 "读取/etc/crontab文件失败" "crontabCheck"
        fi
    else
        echo -e "${RED}[WARN] /etc/crontab文件不存在${NC}"
        log_message "WARN" "/etc/crontab文件不存在"
    fi
    
    echo -e "${YELLOW}[INFO] 系统计划任务[/etc/cron*/*]:${NC}"
    if ls /etc/cron*/* >/dev/null 2>&1; then
        if cat /etc/cron*/* 2>/dev/null | grep -v "^$" >/dev/null 2>&1; then
            cat /etc/cron*/* 2>/dev/null | grep -v "^$"
            log_message "INFO" "成功读取/etc/cron*/目录下的计划任务文件"
        else
            echo -e "${YELLOW}[INFO] /etc/cron*/目录下无有效计划任务${NC}"
            log_message "INFO" "/etc/cron*/目录下无有效计划任务"
        fi
    else
        echo -e "${YELLOW}[INFO] /etc/cron*/目录下无计划任务文件${NC}"
        log_message "INFO" "/etc/cron*/目录下无计划任务文件"
    fi

    # 用户计划任务收集
    echo -e "${YELLOW}[INFO] 输出用户计划任务[/var/spool/cron/*]:${NC}" 
    log_message "INFO" "开始收集用户计划任务信息"
    
    if [ -d "/var/spool/cron" ]; then
        local user_cron_count=0
        for user_cron in $(ls /var/spool/cron 2>/dev/null); do
            if [ -f "/var/spool/cron/$user_cron" ]; then
                echo -e "${YELLOW}Cron tasks for user: $user_cron ${NC}"
                if cat "/var/spool/cron/$user_cron" >/dev/null 2>&1; then
                    cat "/var/spool/cron/$user_cron"
                    user_cron_count=$((user_cron_count + 1))
                    log_message "INFO" "成功读取用户${user_cron}的计划任务"
                else
                    handle_error 1 "读取用户 ${user_cron} 的计划任务失败" "crontabCheck"
                fi
            fi
        done
        
        if [ $user_cron_count -eq 0 ]; then
            echo -e "${YELLOW}[INFO] 未发现用户计划任务${NC}"
            log_message "INFO" "未发现用户计划任务"
        else
            log_message "INFO" "共发现${user_cron_count}个用户的计划任务"
        fi
    else
        echo -e "${RED}[WARN] /var/spool/cron目录不存在${NC}"
        log_message "WARN" "/var/spool/cron目录不存在"
    fi

    # 用户/系统计划任务分析
    echo -e "${YELLOW}[INFO] 开始分析可疑计划任务:${NC}"
    log_message "INFO" "开始分析可疑计划任务"
    
    local cron_files=""
    [ -f "/etc/crontab" ] && cron_files="$cron_files /etc/crontab"
    [ -n "$(ls /etc/cron*/* 2>/dev/null)" ] && cron_files="$cron_files /etc/cron*/*"
    [ -n "$(ls /var/spool/cron/* 2>/dev/null)" ] && cron_files="$cron_files /var/spool/cron/*"
    
    if [ -n "$cron_files" ]; then
        hackCron=$(egrep "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" $cron_files 2>/dev/null)  # 输出所有可疑计划任务
        if [ $? -eq 0 ] && [ -n "$hackCron" ]; then
            (echo "${RED}[WARN] 发现下面的定时任务可疑,请注意!${NC}" && echo "$hackCron")  
            log_message "WARN" "发现可疑计划任务: $hackCron"
        else
            echo "${GREEN}[SUCC] 未发现可疑系统定时任务${NC}" 
            log_message "INFO" "未发现可疑系统定时任务"
        fi
    else
        echo "${YELLOW}[INFO] 无计划任务文件可供分析${NC}"
        log_message "INFO" "无计划任务文件可供分析"
    fi

    # 系统计划任务状态分析
    echo -e "${YELLOW}[INFO] 检测定时任务访问信息:${NC}" 
    echo -e "${YELLOW}[INFO] 检测定时任务访问信息[stat /etc/crontab | /etc/cron*/* | /var/spool/cron/*]:${NC}" 
    log_message "INFO" "开始检测计划任务文件状态信息"
    
    local analyzed_files=0
    for cronfile in /etc/crontab /etc/cron*/* /var/spool/cron/*; do
        if [ -f "$cronfile" ]; then
            echo -e "${YELLOW}Target cron Info [${cronfile}]:${NC}"
            if cat "$cronfile" | grep -v "^$" >/dev/null 2>&1; then
                cat "$cronfile" | grep -v "^$"  # 去除空行
            else
                handle_error 1 "读取计划任务文件 ${cronfile} 失败" "crontabCheck"
                continue
            fi
            
            echo -e "${YELLOW}stat [${cronfile}] ${NC}"
            if stat "$cronfile" | grep -E "Access|Modify|Change" | grep -v "(" >/dev/null 2>&1; then
                stat "$cronfile" | grep -E "Access|Modify|Change" | grep -v "("
                analyzed_files=$((analyzed_files + 1))
                log_message "INFO" "成功分析计划任务文件${cronfile}的状态信息"
            else
                handle_error 1 "获取计划任务文件 ${cronfile} 状态信息失败" "crontabCheck"
            fi
            
            # 从这里可以看到计划任务的状态[最近修改时间等]
            # "Access:访问时间,每次访问文件时都会更新这个时间,如使用more、cat" 
            # "Modify:修改时间,文件内容改变会导致该时间更新" 
            # "Change:改变时间,文件属性变化会导致该时间更新,当文件修改时也会导致该时间更新;但是改变文件的属性,如读写权限时只会导致该时间更新,不会导致修改时间更新
        fi
    done
    
    if [ $analyzed_files -eq 0 ]; then
        echo -e "${YELLOW}[INFO] 未发现可分析的计划任务文件${NC}"
        log_message "INFO" "未发现可分析的计划任务文件"
    else
        log_message "INFO" "共分析了${analyzed_files}个计划任务文件的状态信息"
    fi
    
    # 记录计划任务检查完成
    local end_time=$(date +%s)
    log_operation "MOUDLE - CRONTABCHECK" "计划任务分析和安全检测完成" "END"
    log_performance "crontabCheck" $start_time $end_time
    printf "\n"
}

# 历史命令排查【归档 -- systemCheck】
historyCheck(){
    local start_time=$(date +%s)
    log_operation "MOUDLE - HISTORYCHECK" "开始历史命令分析和安全检测" "START"
    
    echo -e "${GREEN}==========${YELLOW}History Analysis${GREEN}==========${NC}"
    
    # history 和 cat /[user]/.bash_history 的区别
    # history:
    # - 实时历史: history 命令显示的是当前 shell 会话中已经执行过的命令历史,包括那些在当前会话中输入的命令。默认显示 500 条命令,可以通过 -c 参数清除历史记录。
    # - 动态更新: 当你在 shell 会话中执行命令时,这些命令会被实时添加到历史记录中,因此 history 命令的输出会随着你的命令输入而不断更新。
    # - 受限于当前会话: history 命令只显示当前 shell 会话的历史记录。如果关闭了终端再重新打开,history 命令将只显示新会话中的命令历史,除非你使用了历史文件共享设置。
    # - 命令编号: history 命令的输出带有命令编号,这使得引用特定历史命令变得容易。你可以使用 !number 形式来重新执行历史中的任意命令
    # cat /[user]/.bash_history:
    # - 持久化历史: /[user]/.bash_history 文件是 bash shell 保存的命令历史文件,它保存了用户过去执行的命令,即使在关闭终端或注销后,这些历史记录也会被保留下来。
    # - 静态文件: /[user]/.bash_history 是一个文件,它的内容不会随着你当前会话中的命令输入而实时更新。文件的内容会在你退出终端会话时更新,bash 会把当前会话的命令追加到这个文件中。
    # - 不受限于当前会话: cat /[user]/.bash_history 可以显示用户的所有历史命令,包括以前会话中的命令,而不只是当前会话的命令。
    # - 无命令编号: 由于 /[user]/.bash_history 是一个普通的文本文件,它的输出没有命令编号,你不能直接使用 !number 的方式来引用历史命令。
    # 注意: 大多数情况下 linux 系统会为每个用户创建一个 .bash_history 文件。
    #       set +o history 是关闭命令历史记录功能,set -o history 重新打开[只影响当前的 shell 会话]
    
    # 输出 root 历史命令[history]
    echo -e "${YELLOW}[INFO] 输出当前shell下历史命令[history]:${NC}"
    log_message "INFO" "开始获取当前shell历史命令"
    
    if historyTmp=$(history 2>/dev/null); then
        if [ -n "$historyTmp" ]; then
            (echo -e "${YELLOW}[INFO] 当前shell下history历史命令如下:${NC}" && echo "$historyTmp") 
            local history_count=$(echo "$historyTmp" | wc -l)
            log_message "INFO" "成功获取当前shell历史命令,共${history_count}条"
        else
            echo -e "${RED}[WARN] 未发现历史命令,请检查是否记录及已被清除${NC}" 
            log_message "WARN" "当前shell历史命令为空"
        fi
    else
        echo -e "${RED}[WARN] 获取历史命令失败${NC}"
        handle_error 1 "获取当前shell历史命令失败" "historyCheck"
    fi

    # 读取/root/.bash_history文件的内容到变量history中
    echo -e "${YELLOW}[INFO] 输出操作系统历史命令[cat /root/.bash_history]:${NC}"
    log_message "INFO" "开始读取/root/.bash_history文件"
    
    if [ -f /root/.bash_history ]; then
        if history=$(cat /root/.bash_history 2>/dev/null); then
            if [ -n "$history" ]; then
                # 如果文件非空,输出历史命令
                (echo -e "${YELLOW}[INFO] 操作系统历史命令如下:${NC}" && echo "$history") 
                local file_history_count=$(echo "$history" | wc -l)
                log_message "INFO" "成功读取/root/.bash_history文件,共${file_history_count}条历史命令"
            else
                # 如果文件为空,输出警告信息
                echo -e "${RED}[WARN] 未发现历史命令,请检查是否记录及已被清除${NC}" 
                log_message "WARN" "/root/.bash_history文件为空"
            fi
        else
            handle_error 1 "读取/root/.bash_history文件失败" "historyCheck"
        fi
    else
        # 如果文件不存在,同样输出警告信息
        echo -e "${RED}[WARN] 未发现历史命令文件,请检查/root/.bash_history是否存在${NC}" 
        log_message "WARN" "/root/.bash_history文件不存在"
    fi

	# 历史命令分析
	echo -e "${YELLOW}[INFO] 开始历史命令安全分析:${NC}"
	log_message "INFO" "开始历史命令安全分析和威胁检测"
	
	## 检查是否下载过脚本
	echo -e "${YELLOW}[INFO] 检查是否下载过脚本[cat /root/.bash_history | grep -E '((wget|curl|yum|apt-get|python).*\.(sh|pl|py|exe)$)']:${NC}"
	log_message "INFO" "检查历史命令中的脚本下载行为"
	
	if [ -f /root/.bash_history ]; then
		if scripts=$(cat /root/.bash_history 2>/dev/null | grep -E "((wget|curl|yum|apt-get|python).*\.(sh|pl|py|exe)$)" | grep -v grep 2>/dev/null); then
			if [ -n "$scripts" ]; then
				(echo -e "${RED}[WARN] 发现下载过脚本,请注意!${NC}" && echo "$scripts") 
				local script_count=$(echo "$scripts" | wc -l)
				log_message "WARN" "发现${script_count}条脚本下载记录"
			else
				echo -e "${GREEN}[SUCC] 未发现下载过脚本${NC}" 
				log_message "INFO" "未发现脚本下载行为"
			fi
		else
			handle_error 1 "检查脚本下载历史失败" "historyCheck"
		fi
	else
		log_message "WARN" "/root/.bash_history文件不存在,跳过脚本下载检查"
	fi

	## 检查是否通过主机下载/传输过文件
	echo -e "${YELLOW}[INFO] 检查是否通过主机下载/传输过文件[cat /root/.bash_history | grep -E '(sz|rz|scp)']:${NC}"
	log_message "INFO" "检查历史命令中的文件传输行为"
	
	if [ -f /root/.bash_history ]; then
		if fileTransfer=$(cat /root/.bash_history 2>/dev/null | grep -E "(sz|rz|scp)" | grep -v grep 2>/dev/null); then
			if [ -n "$fileTransfer" ]; then
				(echo -e "${RED}[WARN] 发现通过主机下载/传输过文件,请注意!${NC}" && echo "$fileTransfer") 
				local transfer_count=$(echo "$fileTransfer" | wc -l)
				log_message "WARN" "发现${transfer_count}条文件传输记录"
			else
				echo -e "${GREEN}[SUCC] 未发现通过主机下载/传输过文件${NC}" 
				log_message "INFO" "未发现文件传输行为"
			fi
		else
			handle_error 1 "检查文件传输历史失败" "historyCheck"
		fi
	fi

	## 检查是否增加/删除过账号
	echo -e "${YELLOW}[INFO] 检查是否增加/删除过账号[cat /root/.bash_history | grep -E '(useradd|groupadd|userdel|groupdel)']:${NC}"
	log_message "INFO" "检查历史命令中的用户账号操作"
	
	if [ -f /root/.bash_history ]; then
		if addDelhistory=$(cat /root/.bash_history 2>/dev/null | grep -E "(useradd|groupadd|userdel|groupdel)" | grep -v grep 2>/dev/null); then
			if [ -n "$addDelhistory" ]; then
				(echo -e "${RED}[WARN] 发现增加/删除账号,请注意!${NC}" && echo "$addDelhistory") 
				local account_count=$(echo "$addDelhistory" | wc -l)
				log_message "WARN" "发现${account_count}条账号操作记录"
			else
				echo -e "${GREEN}[SUCC] 未发现增加/删除账号${NC}" 
				log_message "INFO" "未发现账号操作行为"
			fi
		else
			handle_error 1 "检查账号操作历史失败" "historyCheck"
		fi
	fi

	## 检查是否存在黑客命令 
	echo -e "${YELLOW}[KNOW] 匹配规则可自行维护,列表如下:id|whoami|ifconfig|whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|*proxy|msfconsole|msf|frp*|xray|*scan|mv|wget|curl|python*|yum|apt-get${NC}"
	log_message "INFO" "检查历史命令中的黑客工具使用"
	
	if [ -f /root/.bash_history ]; then
		if hackCommand=$(cat /root/.bash_history 2>/dev/null | grep -E "id|whoami|ifconfig|whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|*proxy|msfconsole|msf|frp*|xray|*scan|mv|wget|curl|python*|yum|apt-get" | grep -v grep 2>/dev/null); then
			if [ -n "$hackCommand" ]; then
				(echo -e "${RED}[WARN] 发现黑客命令,请注意!${NC}" && echo "$hackCommand") 
				local hack_count=$(echo "$hackCommand" | wc -l)
				log_message "WARN" "发现${hack_count}条疑似黑客工具使用记录"
			else
				echo -e "${GREEN}[SUCC] 未发现黑客命令${NC}" 
				log_message "INFO" "未发现黑客工具使用"
			fi
		else
			handle_error 1 "检查黑客命令历史失败" "historyCheck"
		fi
	fi

	## 其他可疑命令[set +o history]等 例如 chattr 修改文件属性
	echo -e "${YELLOW}[INFO] 检查是否存在黑客命令[cat /root/.bash_history | grep -E '(chattr|chmod|rm|set +o history)'${NC}"
	log_message "INFO" "检查历史命令中的其他可疑操作"
	
	if [ -f /root/.bash_history ]; then
		if otherCommand=$(cat /root/.bash_history 2>/dev/null | grep -E "(chattr|chmod|shred|rm|set +o history)" | grep -v grep 2>/dev/null); then
			if [ -n "$otherCommand" ]; then
				(echo -e "${RED}[WARN] 发现其他可疑命令,请注意!${NC}" && echo "$otherCommand") 
				local other_count=$(echo "$otherCommand" | wc -l)
				log_message "WARN" "发现${other_count}条其他可疑操作记录"
			else
				echo -e "${GREEN}[SUCC] 未发现其他可疑命令${NC}" 
				log_message "INFO" "未发现其他可疑操作"
			fi
		else
			handle_error 1 "检查其他可疑命令历史失败" "historyCheck"
		fi
	fi

	# 检查历史记录目录,看是否被备份,注意：这里可以看开容器持久化的.bash_history
	echo -e "${YELLOW}[INFO] 输出系统中所有可能的.bash_history*文件路径:${NC}"
	log_message "INFO" "搜索系统中所有历史命令文件"
	
	if findOut=$(find / -name ".bash_history*" -type f -exec ls -l {} \; 2>/dev/null); then
		if [ -n "$findOut" ]; then
			echo -e "${YELLOW}以下历史命令文件如有未检查需要人工手动检查,有可能涵盖容器内 history 文件${NC}"
			(echo -e "${YELLOW}[INFO] 系统中所有可能的.bash_history*文件如下:${NC}" && echo "$findOut") 
			local history_files_count=$(echo "$findOut" | wc -l)
			log_message "INFO" "发现${history_files_count}个历史命令文件"
		else
			echo -e "${RED}[WARN] 未发现系统中存在历史命令文件,请人工检查机器是否被清理攻击痕迹${NC}" 
			log_message "WARN" "未发现任何历史命令文件,可能已被清理"
		fi
	else
		handle_error 1 "搜索历史命令文件失败" "historyCheck"
	fi

	# 输出其他用户的历史命令[cat /[user]/.bash_history]
	# 使用awk处理/etc/passwd文件,提取用户名和主目录,并检查.bash_history文件
	echo -e "${YELLOW}[INFO] 遍历系统用户并输出其的历史命令[cat /[user]/.bash_history]${NC}"
	log_message "INFO" "检查所有用户的历史命令文件"
	
	if [ -f /etc/passwd ]; then
		if awk -F: '{
			user=$1
			home=$6
			if (-f home"/.bash_history") {
				print "[----- History for User: "user" -----]"
				system("cat " home "/.bash_history")
				print ""
			}
		}' /etc/passwd 2>/dev/null; then
			log_message "INFO" "成功检查所有用户历史命令"
		else
			handle_error 1 "检查用户历史命令失败" "historyCheck"
		fi
	else
		handle_error 1 "/etc/passwd文件不存在" "historyCheck"
	fi
	printf "\n" 

	# 输出数据库操作历史命令
	echo -e "${YELLOW}正在检查数据库操作历史命令[/root/.mysql_history]:${NC}"  
	log_message "INFO" "检查数据库操作历史命令"
	
	if [ -f /root/.mysql_history ]; then
		if mysql_history=$(more /root/.mysql_history 2>/dev/null); then
			if [ -n "$mysql_history" ]; then
				(echo -e "${YELLOW}[INFO] 数据库操作历史命令如下:${NC}" && echo "$mysql_history")  
				local mysql_history_count=$(echo "$mysql_history" | wc -l)
				log_message "INFO" "发现${mysql_history_count}条数据库操作历史"
			else
				echo -e "${YELLOW}[INFO] 未发现数据库历史命令${NC}"  
				log_message "INFO" "数据库历史文件为空"
			fi
		else
			handle_error 1 "读取数据库历史文件失败" "historyCheck"
		fi
	else
		echo -e "${YELLOW}[INFO] 未发现数据库历史命令${NC}"  
		log_message "INFO" "数据库历史文件不存在"
	fi
	printf "\n"  
	
	# 记录函数执行完成和性能统计
	local end_time=$(date +%s)
	log_performance "historyCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - HISTORYCHECK" "历史命令分析和安全检测完成" "END"
}

# 用户信息排查【归档 -- systemCheck】
userInfoCheck(){
	# # 调试信息：显示当前变量值
	# echo -e "${BLUE}[DEBUG] userInfoCheck函数开始执行,当前executed_functions_userInfoCheck值: $executed_functions_userInfoCheck${NC}"
	# log_message "DEBUG" "userInfoCheck函数开始执行,当前executed_functions_userInfoCheck值: $executed_functions_userInfoCheck"
	
	# # 检查函数是否已执行
	# if [ "$executed_functions_userInfoCheck" = "1" ]; then
	# 	echo -e "${YELLOW}[INFO] userInfoCheck函数已执行,跳过重复执行${NC}"
	# 	log_message "INFO" "userInfoCheck函数已执行,跳过重复执行"
	# 	return 0
	# fi
	# # 标记函数为已执行
	# executed_functions_userInfoCheck=1
	# echo -e "${BLUE}[DEBUG] userInfoCheck函数标记为已执行,executed_functions_userInfoCheck设置为: $executed_functions_userInfoCheck${NC}"
	# log_message "DEBUG" "userInfoCheck函数标记为已执行,executed_functions_userInfoCheck设置为: $executed_functions_userInfoCheck"
	
	local start_time=$(date +%s)
	log_operation "MOUDLE - USERINFOCHECK" "用户信息安全检查和分析" "START"
	
	echo -e "${GREEN}==========${YELLOW}User Information Analysis${GREEN}==========${NC}"
	
	echo -e "${YELLOW}[INFO] 输出正在登录的用户:${NC}"
	log_message "INFO" "获取当前登录用户信息"
	if w 2>/dev/null; then
		log_message "INFO" "成功获取当前登录用户信息"
	else
		handle_error 1 "获取当前登录用户信息失败" "userInfoCheck"
	fi
	
	echo -e "${YELLOW}[INFO] 输出系统最后登录用户:${NC}"
	log_message "INFO" "获取系统最后登录用户信息"
	if last 2>/dev/null; then
		log_message "INFO" "成功获取系统最后登录用户信息"
	else
		handle_error 1 "获取系统最后登录用户信息失败" "userInfoCheck"
	fi
	
	# 检查用户信息/etc/passwd
	echo -e "${YELLOW}[INFO] 检查用户信息[/etc/passwd]${NC}"
	echo -e "${YELLOW}[KNOW] 用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录Shell[共7个字段]${NC}"
	log_message "INFO" "开始分析/etc/passwd文件"
	
	if [ -f /etc/passwd ]; then
		echo -e "${YELLOW}[INFO] show /etc/passwd:${NC}"
		if cat /etc/passwd 2>/dev/null; then
			local passwd_users_count=$(cat /etc/passwd | wc -l)
			log_message "INFO" "成功读取/etc/passwd文件,共${passwd_users_count}个用户记录"
		else
			handle_error 1 "读取/etc/passwd文件失败" "userInfoCheck"
		fi
	else
		handle_error 1 "/etc/passwd文件不存在" "userInfoCheck"
	fi
	# 检查可登录用户
	echo -e "${YELLOW}[INFO] 检查可登录用户[cat /etc/passwd | grep -E '/bin/bash$' | awk -F: '{print \$1}']${NC}"
	log_message "INFO" "检查系统中可登录的用户"
	
	if [ -f /etc/passwd ]; then
		if loginUser=$(cat /etc/passwd 2>/dev/null | grep -E "/bin/bash$" | awk -F: '{print $1}' 2>/dev/null); then
			if [ -n "$loginUser" ]; then
				echo -e "${RED}[WARN] 发现可登录用户,请注意!${NC}" && echo "$loginUser"
				local login_user_count=$(echo "$loginUser" | wc -l)
				log_message "WARN" "发现${login_user_count}个可登录用户"
			else
				echo -e "${YELLOW}[INFO] 未发现可登录用户${NC}" 
				log_message "INFO" "未发现可登录用户"
			fi
		else
			handle_error 1 "检查可登录用户失败" "userInfoCheck"
		fi
	fi
	
	# 检查超级用户[除了 root 外的超级用户]
	echo -e "${YELLOW}[INFO] 检查除root外超级用户[cat /etc/passwd | grep -v -E '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if(\$3==0) print \$1}'] ${NC}"
	echo -e "${YELLOW}[KNOW] UID=0的为超级用户,系统默认root的UID为0 ${NC}"
	log_message "INFO" "检查除root外的超级用户"
	
	if [ -f /etc/passwd ]; then
		if superUser=$(cat /etc/passwd 2>/dev/null | grep -v -E '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}' 2>/dev/null); then
			if [ -n "$superUser" ]; then
				echo -e "${RED}[WARN] 发现其他超级用户,请注意!${NC}" && echo "$superUser"
				local super_user_count=$(echo "$superUser" | wc -l)
				log_message "WARN" "发现${super_user_count}个非root超级用户"
			else
				echo -e "${GREEN}[SUCC] 未发现其他超级用户${NC}" 
				log_message "INFO" "未发现其他超级用户"
			fi
		else
			handle_error 1 "检查超级用户失败" "userInfoCheck"
		fi
	fi
	
	# 检查克隆用户
	echo -e "${YELLOW}[INFO] 检查克隆用户[awk -F: '{a[\$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd] ${NC}"
	echo -e "${YELLOW}[KNOW] UID相同为克隆用户${NC}"
	log_message "INFO" "检查UID相同的克隆用户"
	
	if [ -f /etc/passwd ]; then
		if cloneUserUid=$(awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd 2>/dev/null); then
			if [ -n "$cloneUserUid" ]; then
				echo -e "${RED}[WARN] 发现克隆用户,请注意!${NC}"
				if cat /etc/passwd | grep $cloneUserUid | awk -F: '{print $1}' 2>/dev/null; then
					local clone_user_count=$(cat /etc/passwd | grep $cloneUserUid | wc -l)
					log_message "WARN" "发现${clone_user_count}个克隆用户"
				else
					handle_error 1 "获取克隆用户详情失败" "userInfoCheck"
				fi
			else
				echo -e "${GREEN}[SUCC] 未发现克隆用户${NC}" 
				log_message "INFO" "未发现克隆用户"
			fi
		else
			handle_error 1 "检查克隆用户失败" "userInfoCheck"
		fi
	fi
	# 检查非系统自带用户
	## 原理：从/etc/login.defs文件中读取系统用户UID的范围,然后从/etc/passwd文件中读取用户UID进行比对,找出非系统自带用户
	echo -e "${YELLOW}[INFO] 检查非系统自带用户[awk -F: '{if (\$3>='\$defaultUid' && \$3!=65534) {print }}' /etc/passwd] ${NC}"
	echo -e "${YELLOW}[KNOW] 从/etc/login.defs文件中读取系统用户UID的范围,然后从/etc/passwd文件中读取用户UID进行比对,UID在范围外的用户为非系统自带用户${NC}"
	log_message "INFO" "检查非系统自带用户"
	
	if [ -f /etc/login.defs ]; then
		if defaultUid=$(grep -E "^UID_MIN" /etc/login.defs 2>/dev/null | awk '{print $2}' 2>/dev/null); then
			if [ -n "$defaultUid" ] && [ -f /etc/passwd ]; then
				if noSystemUser=$(awk -F: '{if ($3>='$defaultUid' && $3!=65534) {print $1}}' /etc/passwd 2>/dev/null); then
					if [ -n "$noSystemUser" ]; then
						echo -e "${RED}[WARN] 发现非系统自带用户,请注意!${NC}" && echo "$noSystemUser"
						local nosys_user_count=$(echo "$noSystemUser" | wc -l)
						log_message "WARN" "发现${nosys_user_count}个非系统自带用户"
					else
						echo -e "${GREEN}[SUCC] 未发现非系统自带用户${NC}" 
						log_message "INFO" "未发现非系统自带用户"
					fi
				else
					handle_error 1 "检查非系统自带用户失败" "userInfoCheck"
				fi
			else
				handle_error 1 "获取UID_MIN失败或/etc/passwd不存在" "userInfoCheck"
			fi
		else
			handle_error 1 "读取/etc/login.defs失败" "userInfoCheck"
		fi
	else
		log_message "INFO" "/etc/login.defs文件不存在,跳过非系统用户检查"
	fi
	# 检查用户信息/etc/shadow
	# - 检查空口令用户
	echo -e "${YELLOW}[INFO] 检查空口令用户[awk -F: '(\$2=="") {print \$1}' /etc/shadow] ${NC}"
	echo -e "${YELLOW}[KNOW] 用户名:加密密码:最后一次修改时间:最小修改时间间隔:密码有效期:密码需要变更前的警告天数:密码过期后的宽限时间:账号失效时间:保留字段[共9个字段]${NC}"
	echo -e "${YELLOW}[INFO] show /etc/shadow:${NC}"
	log_message "INFO" "检查空口令用户"
	
	if [ -f /etc/shadow ]; then
		if cat /etc/shadow 2>/dev/null; then
			echo -e "${YELLOW}[原理]shadow文件中密码字段(第2个字段)为空的用户即为空口令用户 ${NC}"
			if emptyPasswdUser=$(awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null); then
				if [ -n "$emptyPasswdUser" ]; then
					echo -e "${RED}[WARN] 发现空口令用户,请注意!${NC}" && echo "$emptyPasswdUser"
					local empty_passwd_count=$(echo "$emptyPasswdUser" | wc -l)
					log_message "WARN" "发现${empty_passwd_count}个空口令用户"
				else
					echo -e "${GREEN}[SUCC] 未发现空口令用户${NC}" 
					log_message "INFO" "未发现空口令用户"
				fi
			else
				handle_error 1 "检查空口令用户失败" "userInfoCheck"
			fi
		else
			handle_error 1 "读取/etc/shadow失败" "userInfoCheck"
		fi
	else
		log_message "WARN" "/etc/shadow文件不存在,这是异常情况!"
	fi
	# - 检查空口令且可登录SSH的用户
	# 原理:
	# 1. 从`/etc/passwd`文件中提取使用`/bin/bash`作为shell的用户名。--> 可登录的用户
	# 2. 从`/etc/shadow`文件中获取密码字段为空的用户名。  --> 空密码的用户
	# 3. 检查`/etc/ssh/sshd_config`中SSH服务器配置是否允许空密码。 --> ssh 是否允许空密码登录
	# 4. 遍历步骤1中获取的每个用户名,并检查其是否与步骤2中获取的任何用户名匹配,并且根据步骤3是否允许空密码进行判断。如果存在匹配,则打印通知,表示存在空密码且允许登录的用户。
	# 5. 最后,根据是否找到匹配,打印警告消息,要求人工分析配置和账户,或者打印消息表示未发现空口令且可登录的用户。
	##允许空口令用户登录方法
	##1.passwd -d username
	##2.echo "PermitEmptyPasswords yes" >>/etc/ssh/sshd_config
	##3.service sshd restart
	echo -e "${YELLOW}[INFO] 检查空口令且可登录SSH的用户[/etc/passwd|/etc/shadow|/etc/ssh/sshd_config] ${NC}"
	log_message "INFO" "检查空口令且可登录SSH的用户"
	
	if [ -f /etc/passwd ] && [ -f /etc/shadow ]; then
		if userList=$(cat /etc/passwd 2>/dev/null | grep -E "/bin/bash$" | awk -F: '{print $1}' 2>/dev/null); then
			if noSetPwdUser=$(awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null); then
				if [ -f /etc/ssh/sshd_config ]; then
					if isSSHPermit=$(cat /etc/ssh/sshd_config 2>/dev/null | grep -w "^PermitEmptyPasswords yes" 2>/dev/null); then
						log_message "INFO" "SSH配置允许空密码登录"
					else
						log_message "INFO" "SSH配置不允许空密码登录"
					fi
					flag=""
					for userA in $userList; do
						for userB in $noSetPwdUser; do
							if [ "$userA" == "$userB" ]; then
								if [ -n "$isSSHPermit" ]; then
									echo -e "${RED}[WARN] 发现空口令且可登录SSH的用户,请注意!${NC}" && echo "$userA"
									log_message "WARN" "发现空口令且可SSH登录用户: $userA"
									flag="1"
								else
									echo -e "${YELLOW}[INFO] 发现空口令且不可登录SSH的用户,请注意!${NC}" && echo "$userA"
									log_message "INFO" "发现空口令但不可SSH登录用户: $userA"
								fi
							fi
						done
					done
					if [ -z "$flag" ]; then
						echo -e "${GREEN}[SUCC] 未发现空口令且可登录SSH的用户${NC}" 
						log_message "INFO" "未发现空口令且可SSH登录的用户"
					fi
				else
					handle_error 1 "读取SSH配置失败" "userInfoCheck"
				fi
			else
				handle_error 1 "获取空密码用户失败" "userInfoCheck"
			fi
		else
			handle_error 1 "获取可登录用户失败" "userInfoCheck"
		fi
	else
		log_message "WARN" "缺少必要文件,跳过空口令SSH登录检查"
	fi
	# - 检查口令未加密用户
	echo -e "${YELLOW}[INFO] 检查未加密口令用户[awk -F: '{if(\$2!="x") {print \$1}}' /etc/passwd] ${NC}"
	log_message "INFO" "检查未加密口令用户"
	
	if [ -f /etc/passwd ]; then
		if noEncryptPasswdUser=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd 2>/dev/null); then
			if [ -n "$noEncryptPasswdUser" ]; then
				echo -e "${RED}[WARN] 发现未加密口令用户,请注意!${NC}" && echo "$noEncryptPasswdUser"
				local noencrypt_passwd_count=$(echo "$noEncryptPasswdUser" | wc -l)
				log_message "WARN" "发现${noencrypt_passwd_count}个未加密口令用户"
			else
				echo -e "${GREEN}[SUCC] 未发现未加密口令用户${NC}" 
				log_message "INFO" "未发现未加密口令用户"
			fi
		else
			handle_error 1 "检查未加密口令用户失败" "userInfoCheck"
		fi
	else
		log_message "WARN" "/etc/passwd文件不存在,这是异常情况!"
	fi
	# 检查用户组信息/etc/group
	echo -e "${YELLOW}[INFO] 检查用户组信息[/etc/group] ${NC}"
	echo -e "${YELLOW}[KNOW] 组名:组密码:GID:组成员列表[共4个字段] ${NC}"
	echo -e "${YELLOW}[INFO] show /etc/group:${NC}"
	log_message "INFO" "检查用户组信息"
	
	if [ -f /etc/group ]; then
		if cat /etc/group 2>/dev/null; then
			log_message "INFO" "成功读取/etc/group文件"
		else
			handle_error 1 "读取/etc/group失败" "userInfoCheck"
		fi
	else
		log_message "WARN" "/etc/group文件不存在,跳过用户组检查"
		return
	fi
	
	# - 检查特权用户组[除root组之外]
	echo -e "${YELLOW}[INFO] 检查特权用户组[cat /etc/group | grep -v '^#' | awk -F: '{if (\$1!="root"&&\$3==0) print \$1}'] ${NC}"
	echo -e "${YELLOW}[KNOW] GID=0的为超级用户组,系统默认root组的GID为0 ${NC}"
	log_message "INFO" "检查特权用户组"
	
	if privGroupUsers=$(cat /etc/group 2>/dev/null | grep -v '^#' | awk -F: '{if ($1!="root"&&$3==0) print $1}' 2>/dev/null); then
		if [ -n "$privGroupUsers" ]; then
			echo -e "${RED}[WARN] 发现特权用户组,请注意!${NC}" && echo "$privGroupUsers"
			local priv_group_count=$(echo "$privGroupUsers" | wc -l)
			log_message "WARN" "发现${priv_group_count}个特权用户组"
		else
			echo -e "${GREEN}[SUCC] 未发现特权用户组${NC}" 
			log_message "INFO" "未发现特权用户组"
		fi
	else
		handle_error 1 "检查特权用户组失败" "userInfoCheck"
	fi
	# - 检查相同GID的用户组
	echo -e "${YELLOW}[INFO] 检查相同GID的用户组[cat /etc/group | grep -v '^#' | awk -F: '{print \$3}' | uniq -d] ${NC}"
	log_message "INFO" "检查相同GID的用户组"
	
	if groupUid=$(cat /etc/group 2>/dev/null | grep -v "^$" | awk -F: '{print $3}' 2>/dev/null | uniq -d 2>/dev/null); then
		if [ -n "$groupUid" ];then
			echo -e "${RED}[WARN] 发现相同GID用户组:${NC}" && echo "$groupUid"
			local dup_gid_count=$(echo "$groupUid" | wc -l)
			log_message "WARN" "发现${dup_gid_count}个重复GID"
		else
			echo -e "${GREEN}[SUCC] 未发现相同GID的用户组${NC}" 
			log_message "INFO" "未发现相同GID的用户组"
		fi
	else
		handle_error 1 "检查相同GID用户组失败" "userInfoCheck"
	fi
	
	# - 检查相同用户组名
	echo -e "${YELLOW}[INFO] 检查相同用户组名[cat /etc/group | grep -v '^$' | awk -F: '{print \$1}' | uniq -d] ${NC}"
	log_message "INFO" "检查相同用户组名"
	
	if groupName=$(cat /etc/group 2>/dev/null | grep -v "^$" | awk -F: '{print $1}' 2>/dev/null | uniq -d 2>/dev/null); then
		if [ -n "$groupName" ];then
			echo -e "${RED}[WARN] 发现相同用户组名:${NC}" && echo "$groupName"
			local dup_group_count=$(echo "$groupName" | wc -l)
			log_message "WARN" "发现${dup_group_count}个重复用户组名"
		else
			echo -e "${GREEN}[SUCC] 未发现相同用户组名${NC}" 
			log_message "INFO" "未发现相同用户组名"
		fi
	else
		handle_error 1 "检查相同用户组名失败" "userInfoCheck"
	fi
	
	# 记录性能统计
	local end_time=$(date +%s)
	log_performance "userInfoCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - USERINFOCHECK" "用户信息检查模块执行完成" "END"
	
	printf "\n" 
}

# 系统信息排查【完成】   
systemCheck(){
	# 基础信息排查 baseInfo
	baseInfo
	# 用户信息排查 userInfoCheck
	userInfoCheck
	# 计划任务排查 crontabCheck
	crontabCheck
	# 历史命令排查 historyCheck
	historyCheck
}

# 系统自启动服务分析【归档 -- systemServiceCheck】
systemEnabledServiceCheck(){
	local start_time=$(date +%s)
	log_operation "MOUDLE - SYSTEMENABLEDSERVICECHECK" "开始系统自启动服务安全检查和分析" "START"
	
	# 系统自启动项服务分析
	## 检查老版本机器的特殊文件/etc/rc.local /etc/init.d/* [/etc/init.d/* 和 chkconfig --list 命令一样]
	## 有些用户自启动配置在用户的.bashrc/.bash_profile/.profile/.bash_logout等文件中
	## 判断系统的初始化程序[sysvinit|systemd|upstart(弃用)]
	echo -e "${YELLOW}[INFO] 正在检查自启动服务信息:${NC}"
	log_message "INFO" "开始检查系统自启动服务信息"
	
	echo -e "${YELLOW}[INFO] 正在辨认系统使用的初始化程序${NC}"
	log_message "INFO" "开始识别系统初始化程序类型"
	
	if systemInit=$((cat /proc/1/comm 2>/dev/null)|| (cat /proc/1/cgroup 2>/dev/null | grep -w "name=systemd" | awk -F : '{print $2}' | awk -F = '{print $2}')) 2>/dev/null; then
		: # 命令执行成功,继续处理
	else
		handle_error 1 "获取系统初始化程序信息失败" "systemEnabledServiceCheck"
		return 1
	fi
	if [ -n "$systemInit" ];then
		echo -e "${YELLOW}[INFO] 系统初始化程序为:$systemInit ${NC}"
		log_message "INFO" "识别到系统初始化程序"
		
		if [ "$systemInit" == "systemd" ];then
			echo -e "${YELLOW}[INFO] 正在检查systemd自启动项[systemctl list-unit-files]:${NC}"
			log_message "INFO" "开始检查systemd自启动服务项"
			
			if systemd=$(systemctl list-unit-files 2>/dev/null | grep -E "enabled" 2>/dev/null); then
				if systemdList=$(systemctl list-unit-files 2>/dev/null | grep -E "enabled" | awk '{print $1}' 2>/dev/null); then
					: # 命令执行成功
				else
					handle_error 1 "获取systemd服务列表失败" "systemEnabledServiceCheck"
					return 1
				fi
			else
				handle_error 1 "执行systemctl list-unit-files命令失败" "systemEnabledServiceCheck"
				return 1
			fi
			
			if [ -n "$systemd" ];then
				echo -e "${YELLOW}[INFO] systemd自启动项:${NC}" && echo "$systemd"
				local systemd_count=$(echo "$systemd" | wc -l)
				log_message "INFO" "发现${systemd_count}个systemd自启动服务"
				# 分析系统启动项 【这里只是启动服务项,不包括其他服务项,所以在这里检查不完整,单独检查吧】
				# 分析systemd启动项
				echo -e "${YELLOW}[INFO] 正在分析危险systemd启动项[systemctl list-unit-files]:${NC}"
				log_message "INFO" "开始分析systemd启动项中的危险服务"
				
				echo -e "${YELLOW}[KNOW] 根据服务名称找到服务文件位置[systemctl show xx.service -p FragmentPath]${NC}"
				echo -e "${YELLOW}[KNOW] 根据服务文件位置找到服务文件并匹配敏感命令${NC}"
				
				# 循环分析每个服务
				local analyzed_services=0
				local dangerous_services=0
				
				for service in $systemdList; do
					echo -e "${YELLOW}[INFO] 正在分析systemd启动项:$service${NC}"
					log_message "INFO" "分析systemd服务: $service"
					
					# 根据服务名称找到服务文件位置
					if servicePath=$(systemctl show $service -p FragmentPath 2>/dev/null | awk -F "=" '{print $2}' 2>/dev/null); then
						if [ -n "$servicePath" ] && [ -f "$servicePath" ]; then
							echo -e "${YELLOW}[INFO] 找到service服务文件位置:$servicePath${NC}"
							log_message "INFO" "找到服务文件: $servicePath"
							# 检查服务文件是否可读
							if [ ! -r "$servicePath" ]; then
								handle_error 1 "无法读取服务文件 ${servicePath}" "systemEnabledServiceCheck"
							else
								# 在服务文件中搜索敏感命令或脚本模式
								dangerService=$(grep -E "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" "$servicePath" 2>/dev/null)
								# 检查是否找到敏感内容（grep返回1表示无匹配，这是正常情况）
								if [ -n "$dangerService" ]; then
									echo -e "${RED}[WARN] 发现systemd启动项:${service}包含敏感命令或脚本:${NC}" && echo "$dangerService"
									log_message "WARN" "发现危险systemd服务: $service,包含敏感命令"
									dangerous_services=$((dangerous_services + 1))
								else
									# 未找到敏感内容是正常情况，不是错误
									echo -e "${GREEN}[SUCC] 未发现systemd启动项:${service}包含敏感命令或脚本${NC}"
									log_message "INFO" "systemd服务 $service 未发现敏感命令"
								fi
							fi
						else
							echo -e "${RED}[WARN] 未找到service服务文件位置:$service${NC}"
							log_message "WARN" "未找到systemd服务文件: $service"
						fi
				else
					handle_error 1 "获取服务 ${service} 文件路径失败" "systemEnabledServiceCheck"
				fi
					analyzed_services=$((analyzed_services + 1))
				done
				
				log_message "INFO" "systemd服务分析完成,共分析${analyzed_services}个服务,发现${dangerous_services}个危险服务"			

			else
				echo -e "${RED}[WARN] 未发现systemd自启动项${NC}"
				log_message "WARN" "未发现systemd自启动项"
			fi
		elif [ "$systemInit" == "init" ];then
			echo -e "${YELLOW}[INFO] 正在检查init自启动项[chkconfig --list]:${NC}"  # [chkconfig --list实际查看的是/etc/init.d/下的服务]
			log_message "INFO" "开始检查init自启动服务项"
			
			if init=$(chkconfig --list 2>/dev/null | grep -E ":on|启用" 2>/dev/null); then
				: # 命令执行成功
			else
				handle_error 1 "执行chkconfig --list命令失败" "systemEnabledServiceCheck"
				return 1
			fi
			
			if [ -n "$init" ];then
				echo -e "${YELLOW}[INFO] init自启动项:${NC}" && echo "$init"
				local init_count=$(echo "$init" | wc -l)
				log_message "INFO" "发现${init_count}个init自启动服务"
				
				# 如果系统使用的是systemd启动,这里会输出提示使用systemctl list-unit-files的命令
				# 分析sysvinit启动项
				echo -e "${YELLOW}[INFO] 正在分析危险init自启动项[chkconfig --list| awk '{print \$1}' | grep -E '\.(sh|pl|py|exe)$']:${NC}"
				log_message "INFO" "开始分析init启动项中的危险服务"
				
				echo -e "${YELLOW}[KNOW] 只根据服务启动名后缀检查可疑服务,并未匹配服务文件内容${NC}"
				
				if dangerServiceInit=$(chkconfig --list 2>/dev/null | awk '{print $1}' 2>/dev/null | grep -E "\.(sh|pl|py|exe)$" 2>/dev/null); then
					if [ -n "$dangerServiceInit" ];then
						echo -e "${RED}[WARN] 发现敏感init自启动项:${NC}" && echo "$dangerServiceInit"
						local danger_init_count=$(echo "$dangerServiceInit" | wc -l)
						log_message "WARN" "发现${danger_init_count}个敏感init自启动项"
					else
						echo -e "${GREEN}[SUCC] 未发现敏感init自启动项:${NC}"
						log_message "INFO" "未发现敏感init自启动项"
					fi
				else
					handle_error 1 "分析init自启动项失败" "systemEnabledServiceCheck"
				fi

			else
				echo -e "${RED}[WARN] 未发现init自启动项${NC}"
				log_message "WARN" "未发现init自启动项"
			fi
		else
			echo -e "${RED}[WARN] 系统使用初始化程序本程序不适配,请手动检查${NC}"
			echo -e "${BLUE}[KNOW] 如果系统使用初始化程序不[sysvinit|systemd]${NC}"
			log_message "WARN" "系统使用不支持的初始化程序: $systemInit,需要手动检查"
		fi
	else
		echo -e "${RED}[WARN] 未识别到系统初始化程序,请手动检查${NC}"
		log_message "WARN" "未能识别系统初始化程序,请手动检查"
	fi
	
	# 记录性能统计和操作完成
	local end_time=$(date +%s)
	log_performance "systemEnabledServiceCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - SYSTEMENABLEDSERVICECHECK" "系统自启动服务检查模块执行完成" "END"
	printf "\n"
}

# 系统运行服务分析【归档 -- systemServiceCheck】
systemRunningServiceCheck(){
	# 系统正在运行服务分析
	start_time=$(date +%s)
	log_operation "MOUDLE - SYSTEMRUNNINGSERVICECHECK" "系统正在运行服务检查模块" "START"
	log_message "INFO" "正在检查正在运行中服务"
	# systemRunningService=$(systemctl | grep -E "\.service.*running")

	log_message "INFO" "正在辨认系统使用的初始化程序"
	systemInit=$((cat /proc/1/comm 2>/dev/null)|| (cat /proc/1/cgroup 2>/dev/null | grep -w "name=systemd" | awk -F : '{print $2}' | awk -F = '{print $2}')) # 多文件判断
	if [ $? -ne 0 ]; then
		handle_error 1 "获取系统初始化程序失败" "systemRunningServiceCheck"
	fi
	if [ -n "$systemInit" ];then
		echo -e "${YELLOW}[INFO] 系统初始化程序为:$systemInit ${NC}"
		log_message "INFO" "系统初始化程序为:$systemInit"
		if [ "$systemInit" == "systemd" ];then
			echo -e "${YELLOW}[INFO] 正在检查systemd运行中服务项[systemctl | grep -E '\.service.*running']:${NC}"
			log_message "INFO" "正在检查systemd运行中服务项[systemctl | grep -E '\.service.*running']"
			# systemd=$(systemctl list-unit-files | grep -E "enabled" )   # 输出启动项
			systemRunningService=$(systemctl 2>/dev/null | grep -E "\.service.*running")
			if [ $? -ne 0 ]; then
				handle_error 1 "获取systemd运行中服务列表失败" "systemRunningServiceCheck"
			fi
			# systemdList=$(systemctl list-unit-files | grep -E "enabled" | awk '{print $1}') # 输出启动项名称列表
			systemRunningServiceList=$(echo "$systemRunningService" | awk '{print $1}')  # 输出启动项名称列表
			if [ -n "$systemRunningService" ];then
				echo -e "${YELLOW}[INFO] systemd正在运行中服务项:${NC}" && echo "$systemRunningService"
				running_service_count=$(echo "$systemRunningService" | wc -l)
				log_message "INFO" "发现 $running_service_count 个systemd正在运行中服务项"
				# log_message "INFO" "systemd正在运行中服务项详情:"
				# 分析系统启动项 【这里只是运行中服务项,不包括其他服务项,所以在这里检查不完整,单独检查吧】
				# 分析systemd运行中的服务
				echo -e "${YELLOW}[INFO] 正在分析危险systemd运行中服务项[systemctl list-unit-files]:${NC}"
				echo -e "${YELLOW}[KNOW] 根据服务名称找到服务文件位置[systemctl show xx.service -p FragmentPath]${NC}"
				echo -e "${YELLOW}[KNOW] 根据服务文件位置找到服务文件并匹配敏感命令${NC}"
				# 循环
				analyzed_count=0
				danger_running_count=0
				for service in $systemRunningServiceList; do
					echo -e "${YELLOW}[INFO] 正在分析systemd运行中服务项:$service${NC}"
					log_message "INFO" "正在分析systemd运行中服务项:$service"
					# 根据服务名称找到服务文件位置
					servicePath=$(systemctl show $service -p FragmentPath 2>/dev/null | awk -F "=" '{print $2}')  # 文件不存在的时候程序会中断 --- 20240808
					if [ $? -ne 0 ]; then
						handle_error 1 "获取服务文件路径失败: $service" "systemRunningServiceCheck"
					fi
					if [ -n "$servicePath" ] && [ -f "$servicePath" ];then  # 判断文件是否存在
						log_message "INFO" "找到service服务文件位置:$servicePath"
						dangerService=$(grep -E "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" "$servicePath" 2>/dev/null)
						if [ -n "$dangerService" ];then
							echo -e "${RED}[WARN] 发现systemd运行中服务项:${service}包含敏感命令或脚本:${NC}" && echo "$dangerService"
							log_message "WARN" "发现systemd运行中服务项:${service}包含敏感命令或脚本:$dangerService"
							danger_running_count=$((danger_running_count + 1))
						else
							echo -e "${GREEN}[SUCC] 未发现systemd运行中服务项:${service}包含敏感命令或脚本${NC}"
							log_message "INFO" "未发现systemd运行中服务项:${service}包含敏感命令或脚本" 
						fi
					else
						echo -e "${RED}[WARN] 未找到service服务文件位置:$service${NC}"
						log_message "WARN" "未找到service服务文件位置:$service"
					fi
					analyzed_count=$((analyzed_count + 1))
				done
				log_message "INFO" "systemd运行中服务分析完成,共分析 $analyzed_count 个服务,发现 $danger_running_count 个危险服务"			

			else
				echo -e "${RED}[WARN] 未发现systemd运行中服务项${NC}" 
				log_message "WARN" "未发现systemd运行中服务项" 
			fi
		else
			cho -e "${RED}[WARN] 系统使用初始化程序本程序不适配,请手动检查${NC}"
			echo -e "${YELLOW}[KNOW] 如果系统使用初始化程序不[sysvinit|systemd]${NC}"
			log_message "WARN" "系统使用初始化程序本程序不适配,请手动检查"
			log_message "INFO" "如果系统使用初始化程序不是[sysvinit|systemd]"
		fi
	else
		echo -e "${RED}[WARN] 未识别到系统初始化程序,请手动检查${NC}"
		log_message "INFO" "未识别到系统初始化程序,请手动检查"
	fi
	
	end_time=$(date +%s)
	log_performance "systemRunningServiceCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - SYSTEMRUNNINGSERVICECHECK" "系统正在运行服务检查模块执行完成" "END"
}

# 系统服务收集【归档 -- systemServiceCheck】
systemServiceCollect(){
	# 收集所有的系统服务信息,不做分析
	start_time=$(date +%s)
	log_operation "MOUDLE - SYSTEMSERVICECOLLECT" "系统服务收集模块" "START"
	echo -e "${YELLOW}[INFO] 正在收集系统服务信息(不含威胁分析):${NC}"
	log_message "INFO" "正在收集系统服务信息(不含威胁分析)"
	echo -e "${BLUE}[KNOW] 根据服务名称找到服务文件位置[systemctl show xx.service -p FragmentPath]${NC}"
	log_message "INFO" "根据服务名称找到服务文件位置[systemctl show xx.service -p FragmentPath]"
	echo -e "${YELLOW}[INFO] 正在辨认系统使用的初始化程序${NC}"
	log_message "INFO" "正在辨认系统使用的初始化程序"
	systemInit=$((cat /proc/1/comm 2>/dev/null)|| (cat /proc/1/cgroup 2>/dev/null | grep -w "name=systemd" | awk -F : '{print $2}' | awk -F = '{print $2}')) # 多文件判断
	if [ $? -ne 0 ]; then
		handle_error 1 "获取系统初始化程序失败" "systemServiceCollect"
	fi
	if [ -n "$systemInit" ];then
		echo -e "${YELLOW}[INFO] 系统初始化程序为:$systemInit ${NC}"
		log_message "INFO" "系统初始化程序为:$systemInit"
		if [ "$systemInit" == "systemd" ];then
			echo -e "${YELLOW}[INFO] 正在收集systemd系统服务项[systemctl list-unit-files]:${NC}"
			log_message "INFO" "正在收集systemd系统服务项[systemctl list-unit-files]"
			systemd=$(systemctl list-unit-files 2>/dev/null)   # 输出启动项
			if [ $? -ne 0 ]; then
				handle_error 1 "获取systemd系统服务列表失败" "systemServiceCollect"
			fi
			if [ -n "$systemd" ];then
				service_count=$(echo "$systemd" | wc -l)
				echo -e "${YELLOW}[INFO] systemd系统服务项如下:${NC}" && echo "$systemd"
				log_message "INFO" "发现 $service_count 个systemd系统服务项"
				# log_message "INFO" "systemd系统服务项详情:\n$systemd"		
			else
				echo -e "${RED}[WARN] 未发现systemd系统服务项${NC}"
				log_message "WARN" "未发现systemd系统服务项" 
			fi
		elif [ "$systemInit" == "init" ];then
			echo -e "${YELLOW}[INFO] 正在检查init系统服务项[chkconfig --list]:${NC}"  # [chkconfig --list实际查看的是/etc/init.d/下的服务]
			log_message "INFO" "正在检查init系统服务项[chkconfig --list]"
			init=$(chkconfig --list 2>/dev/null)
			if [ $? -ne 0 ]; then
				handle_error 1 "获取init系统服务列表失败" "systemServiceCollect"
			fi
			# initList=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
			if [ -n "$init" ];then
				init_service_count=$(echo "$init" | wc -l)
				echo -e "${YELLOW}[INFO] init系统服务项:${NC}" && echo "$init"
				log_message "INFO" "发现 $init_service_count 个init系统服务项"
				# log_message "INFO" "init系统服务项详情:\n$init"
				# 如果系统使用的是systemd启动,这里会输出提示使用systemctl list-unit-files的命令
			else
				echo "[WARN] 未发现init系统服务项"
				log_message "WARN" "未发现init系统服务项" 
			fi
		else
			echo -e "${RED}[WARN] 系统使用初始化程序本程序不适配,请手动检查${NC}"
			log_message "WARN" "系统使用初始化程序本程序不适配,请手动检查"
			echo -e "${YELLOW}[KNOW] 如果系统使用初始化程序不[sysvinit|systemd]${NC}"
			log_message "INFO" "如果系统使用初始化程序不是[sysvinit|systemd]"
		fi
	else
		echo -e "${RED}[WARN] 未识别到系统初始化程序,请手动检查${NC}"
		log_message "INFO" "未识别到系统初始化程序,请手动检查"
	fi
	
	end_time=$(date +%s)
	log_performance "systemServiceCollect" "$start_time" "$end_time"
	log_operation "MOUDLE - SYSTEMSERVICECOLLECT" "系统服务收集模块执行完成" "END"
}

# 用户服务分析【归档 -- systemServiceCheck】
userServiceCheck(){
	# 用户自启动项服务分析 /etc/rc.d/rc.local /etc/init.d/*
	start_time=$(date +%s)
	log_operation "MOUDLE - USERSERVICECHECK" "用户服务检查模块" "START"
	## 输出 /etc/rc.d/rc.local
	# 【判断是否存在】
	echo -e "${YELLOW}[INFO] 正在检查/etc/rc.d/rc.local是否存在:${NC}"
	log_message "INFO" "正在检查/etc/rc.d/rc.local是否存在"
	if [ -f "/etc/rc.d/rc.local" ];then
		echo -e "${YELLOW}[INFO] /etc/rc.d/rc.local存在${NC}"
		log_message "INFO" "/etc/rc.d/rc.local存在"
		echo -e "${YELLOW}[INFO] 正在检查/etc/rc.d/rc.local用户自启动服务:${NC}"
		log_message "INFO" "正在检查/etc/rc.d/rc.local用户自启动服务"
		rcLocal=$(cat /etc/rc.d/rc.local 2>/dev/null)
		if [ $? -ne 0 ]; then
			handle_error 1 "读取/etc/rc.d/rc.local文件失败" "userServiceCheck"
		fi
		if [ -n "$rcLocal" ];then
			echo -e "${YELLOW}[INFO] /etc/rc.d/rc.local用户自启动项服务如下:${NC}" && echo "$rcLocal"
			log_message "INFO" "/etc/rc.d/rc.local用户自启动项服务内容"
			# log_message "INFO" "/etc/rc.d/rc.local内容详情:\n$rcLocal"
		else
			echo -e "${RED}[WARN] 未发现/etc/rc.d/rc.local用户自启动服务${NC}"
			log_message "WARN" "未发现/etc/rc.d/rc.local用户自启动服务"
		fi

		## 分析 /etc/rc.d/rc.local
		echo -e "${YELLOW}[INFO] 正在分析/etc/rc.d/rc.local用户自启动服务:${NC}"
		log_message "INFO" "正在分析/etc/rc.d/rc.local用户自启动服务"
		dangerRclocal=$(grep -E "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" /etc/rc.d/rc.local 2>/dev/null)
		if [ $? -ne 0 ]; then
			handle_error 1 "分析/etc/rc.d/rc.local文件失败" "userServiceCheck"
		fi
		if [ -n "$dangerRclocal" ];then
			echo -e "${RED}[WARN] 发现/etc/rc.d/rc.local用户自启动服务包含敏感命令或脚本:${NC}" && echo "$dangerRclocal"
			log_message "WARN" "发现/etc/rc.d/rc.local用户自启动服务包含敏感命令或脚本"
		else
			echo -e "${GREEN}[SUCC] 未发现/etc/rc.d/rc.local用户自启动服务包含敏感命令或脚本${NC}"
			log_message "INFO" "未发现/etc/rc.d/rc.local用户自启动服务包含敏感命令或脚本" 
		fi
	else
		echo -e "${RED}[WARN] /etc/rc.d/rc.local不存在${NC}"
		log_message "WARN" "/etc/rc.d/rc.local不存在"
	fi

	## 分析 /etc/init.d/*
	echo -e "${YELLOW}[INFO] 正在检查/etc/init.d/*用户自启动服务:${NC}"
	log_message "INFO" "正在检查/etc/init.d/*用户自启动服务"
	if [ -d "/etc/init.d" ]; then
		dangerinitd=$(egrep "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" /etc/init.d/* 2>/dev/null)
		if [ -n "$dangerinitd" ];then
			(echo -e "${RED}[WARN] 发现/etc/init.d/用户危险自启动服务:${NC}" && echo "$dangerinitd")
			log_message "WARN" "发现/etc/init.d/用户危险自启动服务" 
		else
			echo -e "${GREEN}[SUCC] 未发现/etc/init.d/用户危险自启动服务${NC}"
			log_message "INFO" "未发现/etc/init.d/用户危险自启动服务" 
		fi
	else
		echo -e "${RED}[WARN] /etc/init.d目录不存在${NC}"
		log_message "WARN" "/etc/init.d目录不存在"
	fi

	# 有些用户自启动配置在用户的.bashrc|.bash_profile|.profile|.bash_logout|.viminfo 等文件中
	# 检查给定用户的配置文件中是否存在敏感命令或脚本
	log_message "INFO" "开始检查用户配置文件中的自启动服务"
	check_files() {
		local user=$1
		local home_dir="/home/$user"
		# 特殊处理 root 用户
		if [ "$user" = "root" ]; then
			home_dir="/root"
		fi

		local files=(".bashrc" ".bash_profile" ".profile" ".bash_logout" ".zshrc" ".viminfo")  # 定义检查的配置文件列表
		for file in "${files[@]}"; do
			if [ -f "$home_dir/$file" ]; then  # $home_dir/$file
				echo -e "${YELLOW}[INFO] 正在检查用户: $user 的 $file 文件: ${NC}"
				log_message "INFO" "正在检查用户: $user 的 $file 文件"
				local results=$(grep -E "((chmod|useradd|groupadd|chattr)|((rm|wget|curl)*\.(sh|pl|py|exe)$))" "$home_dir/$file" 2>/dev/null)
				if [ -n "$results" ]; then
					echo -e "${YELLOW}[INFO] 用户: $user 的 $file 文件存在敏感命令或脚本:${NC}" && echo "$results"
					log_message "WARN" "用户: $user 的 $file 文件存在敏感命令或脚本"
				else
					echo -e "${GREEN}[SUCC] 用户: $user 的 $file 文件不存在敏感命令或脚本${NC}"
					log_message "INFO" "用户: $user 的 $file 文件不存在敏感命令或脚本"
				fi
			else
				echo -e "${YELLOW}[INFO] 用户: $user 的 $file 文件不存在${NC}"
				log_message "INFO" "用户: $user 的 $file 文件不存在"
			fi
		done
	}

	# 获取所有用户
	echo -e "${YELLOW}[INFO] 正在检查所有用户的配置文件:${NC}"
	log_message "INFO" "正在检查所有用户的配置文件"
	user_count=0
	for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
		echo -e "${YELLOW}[INFO] 正在检查用户: $user 的自启动服务(.bashrc|.bash_profile|.profile):${NC}"
		log_message "INFO" "正在检查用户: $user 的自启动服务"
		check_files "$user"
		((user_count++))
	done
	
	log_message "INFO" "已检查 $user_count 个用户的配置文件"
	
	# 记录性能统计和操作完成
	end_time=$(date +%s)
	log_performance "userServiceCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - USERSERVICECHECK" "用户自启动服务检查模块执行完成" "END"
}

# 系统服务排查 【归档 -- fileCheck】
systemServiceCheck(){
	# 系统服务收集  systemServiceCollect
	systemServiceCollect
	# 系统服务分析
	# - 系统自启动服务分析    systemEnabledServiceCheck
	systemEnabledServiceCheck
	# - 系统正在运行服务分析   systemRunningServiceCheck
	systemRunningServiceCheck
	# 用户服务收集
	# 用户服务分析  userServiceCheck
	userServiceCheck
}

# 敏感目录排查(包含隐藏文件)【归档 -- fileCheck】
dirFileCheck(){
	# 敏感目录排查(包含隐藏文件)
	start_time=$(date +%s)
	log_operation "MOUDLE - DIRFILECHECK" "敏感目录文件检查模块" "START"
	
	# /tmp/下
	echo -e "${YELLOW}[INFO] 正在检查/tmp/下文件[ls -alt /tmp]:${NC}"
	log_message "INFO" "正在检查/tmp/下文件"
	echo -e "${YELLOW}[[KNOW] tmp目录是用于存放临时文件的目录,可用于存放木马文件,可用于存放病毒文件,可用于存放破解文件${NC}"
	log_message "INFO" "tmp目录是用于存放临时文件的目录,可用于存放木马文件,可用于存放病毒文件,可用于存放破解文件"
	tmp_tmp=$(ls -alt /tmp 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "检查/tmp目录失败" "dirFileCheck"
	fi
	if [ -n "$tmp_tmp" ];then
		echo -e "${YELLOW}[INFO] /tmp/下文件如下:${NC}" && echo "$tmp_tmp"
		log_message "INFO" "发现/tmp/下存在文件"
	else
		echo -e "${RED}[WARN] 未发现/tmp/下文件${NC}"
		log_message "WARN" "未发现/tmp/下存在文件"
	fi

	# /root下隐藏文件分析
	echo -e "${YELLOW}[INFO] 正在检查/root/下隐藏文件[ls -alt /root]:${NC}"
	log_message "INFO" "正在检查/root/下隐藏文件"
	echo -e "${BLUE}[KNOW] 隐藏文件以.开头,可用于存放木马文件,可用于存放病毒文件,可用于存放破解文件${NC}"  
	# log_message "INFO" "隐藏文件以.开头,可用于存放木马文件,可用于存放病毒文件,可用于存放破解文件"
	root_tmp=$(ls -alt /root 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "检查/root目录失败" "dirFileCheck"
	fi
	if [ -n "$root_tmp" ];then
		echo -e "${RED}[WARN] /root下隐藏文件如下:${NC}" && echo "$root_tmp"
		log_message "WARN" "发现/root下隐藏文件列表"
	else
		echo -e "${GREEN}[SUCC] 未发现/root下隐藏文件${NC}"
		log_message "INFO" "未发现/root下隐藏文件"
	fi

	# 【新增】lsof +L1检查 - 进程存在但文件已删除 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[INFO] 正在检查进程存在但文件已删除的情况[lsof +L1]:${NC}"
	log_message "INFO" "正在检查进程存在但文件已删除的情况" "dirFileCheck"
	
	if command -v lsof >/dev/null 2>&1; then
		local deleted_files=$(lsof +L1 2>/dev/null)
		if [[ -n "$deleted_files" ]]; then
			echo -e "${RED}[WARN] 发现进程存在但文件已删除的情况(可能是内存马或rootkit):${NC}"
			echo "$deleted_files" | while read -r line; do
				echo -e "${RED}[WARN] $line${NC}"
				log_message "WARN" "进程存在但文件已删除: $line" "dirFileCheck"
			done
		else
			echo -e "${GREEN}[SUCC] 未发现进程存在但文件已删除的情况${NC}"
			log_message "INFO" "未发现进程存在但文件已删除的情况" "dirFileCheck"
		fi
	else
		echo -e "${YELLOW}[NOTE] lsof命令不可用，跳过检查${NC}"
		log_message "INFO" "lsof命令不可用，跳过检查" "dirFileCheck"
	fi
	printf "\n"

	# 【新增】近七天文件ctime检查 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[INFO] 正在检查近七天内修改的可疑文件[find -ctime -7]:${NC}"
	log_message "INFO" "正在检查近七天内修改的可疑文件" "dirFileCheck"
	
	# 检查系统关键目录下近7天内被修改的文件
	local critical_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/etc" "/root")
	local recent_files_found=false
	
	for dir in "${critical_dirs[@]}"; do
		if [[ -d "$dir" ]]; then
			echo -e "${YELLOW}[检查] $dir 目录下近7天修改的文件:${NC}"
			local recent_files=$(find "$dir" -type f -ctime -7 2>/dev/null | head -20)
			if [[ -n "$recent_files" ]]; then
				recent_files_found=true
				echo "$recent_files" | while read -r file; do
					if [[ -f "$file" ]]; then
						local file_info=$(ls -la "$file" 2>/dev/null)
						local file_type=$(file -b "$file" 2>/dev/null)
						echo -e "${YELLOW}[INFO] $file_info | 类型: $file_type${NC}"
						log_message "INFO" "近期修改文件: $file - $file_type" "dirFileCheck"
					fi
				done
			else
				echo -e "${GREEN}[SUCC] $dir 目录下无近期修改文件${NC}"
			fi
		fi
	done
	
	# 检查可疑扩展名的近期文件
	echo -e "${YELLOW}[检查] 近7天内创建的可疑脚本文件:${NC}"
	local suspicious_recent=$(find /tmp /var/tmp /dev/shm /home -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.jsp" \) -ctime -7 2>/dev/null | head -10)
	if [[ -n "$suspicious_recent" ]]; then
		echo -e "${RED}[WARN] 发现近期创建的可疑脚本文件:${NC}"
		echo "$suspicious_recent" | while read -r file; do
			local file_info=$(ls -la "$file" 2>/dev/null)
			echo -e "${RED}[WARN] $file_info${NC}"
			log_message "WARN" "近期可疑脚本文件: $file" "dirFileCheck"
		done
		recent_files_found=true
	else
		echo -e "${GREEN}[SUCC] 未发现近期可疑脚本文件${NC}"
	fi
	
	if [[ "$recent_files_found" == false ]]; then
		echo -e "${GREEN}[SUCC] 近七天文件修改检查通过${NC}"
		log_message "INFO" "近七天文件修改检查通过" "dirFileCheck"
	fi
	printf "\n"

	# 记录性能统计和操作完成
	end_time=$(date +%s)
	log_performance "dirFileCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - DIRFILECHECK" "敏感目录文件检查模块执行完成" "END"
	
	# 其他
	
}

# SSH登录配置排查 【归档 -- specialFileCheck】
sshFileCheck(){
	# # 调试信息：显示当前变量值
	# echo -e "${BLUE}[DEBUG] sshFileCheck函数开始执行,当前executed_functions_sshFileCheck值: $executed_functions_sshFileCheck${NC}"
	# log_message "DEBUG" "sshFileCheck函数开始执行,当前executed_functions_sshFileCheck值: $executed_functions_sshFileCheck"
	
	# # 检查函数是否已执行
	# if [ "$executed_functions_sshFileCheck" = "1" ]; then
	# 	echo -e "${YELLOW}[INFO] sshFileCheck函数已执行,跳过重复执行${NC}"
	# 	log_message "INFO" "sshFileCheck函数已执行,跳过重复执行"
	# 	return 0
	# fi
	# # 标记函数为已执行
	# executed_functions_sshFileCheck=1
	# echo -e "${BLUE}[DEBUG] sshFileCheck函数标记为已执行,executed_functions_sshFileCheck设置为: $executed_functions_sshFileCheck${NC}"
	# log_message "DEBUG" "sshFileCheck函数标记为已执行,executed_functions_sshFileCheck设置为: $executed_functions_sshFileCheck"
	
	# SSH登录配置排查
	start_time=$(date +%s)
	log_operation "MOUDLE - SSHFILECHECK" "SSH文件配置检查模块" "START"
	
	# 输出/root/.ssh/下文件
	echo -e "${YELLOW}[INFO] 正在检查/root/.ssh/下文件[ls -alt /root/.ssh]:${NC}"
	log_message "INFO" "正在检查/root/.ssh/下文件"
	ls_ssh=$(ls -alt /root/.ssh 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "检查/root/.ssh目录失败" "sshFileCheck"
	fi
	if [ -n "$ls_ssh" ];then
		echo -e "${YELLOW}[INFO] /root/.ssh/下文件如下:${NC}" && echo "$ls_ssh"
		log_message "INFO" "发现/root/.ssh/存在文件"
	else
		echo -e "${GREEN}[SUCC] 未发现/root/.ssh/存在文件${NC}"
		log_message "INFO" "未发现/root/.ssh/存在文件"
	fi

	# 公钥文件分析
	echo -e "${YELLOW}正在检查公钥文件[/root/.ssh/*.pub]:${NC}"
	log_message "INFO" "正在检查公钥文件"
	pubkey=$(cat /root/.ssh/*.pub 2>/dev/null)
	if [ -n "$pubkey" ];then
		echo -e "${YELLOW}[INFO] 发现公钥文件如下,请注意!${NC}" && echo "$pubkey"
		log_message "INFO" "发现公钥文件"
	else
		echo -e "${GREEN}[SUCC] 未发现公钥文件${NC}"
		log_message "INFO" "未发现公钥文件"
	fi

	# 私钥文件分析
	echo -e "${YELLOW}正在检查私钥文件[/root/.ssh/id_rsa]:${NC}" 
	log_message "INFO" "正在检查私钥文件"
	echo -e "${BLUE}[KNOW] 私钥文件是用于SSH密钥认证的文件,私钥文件不一定叫id_rs,登录方式[ssh -i id_rsa user@ip]${NC}"
	# log_message "INFO" "私钥文件是用于SSH密钥认证的文件,私钥文件不一定叫id_rs,登录方式[ssh -i id_rsa user@ip]"
	privatekey=$(cat /root/.ssh/id_rsa 2>/dev/null)
	if [ -n "$privatekey" ];then
		echo -e "${RED}[WARN] 发现私钥文件,请注意!${NC}" && echo "$privatekey"
		log_message "INFO" "发现私钥文件存在"
	else
		echo -e "${GREEN}[SUCC] 未发现私钥文件存在${NC}"
		log_message "INFO" "未发现私钥文件存在"
	fi
	printf "\n" 

	# authorized_keys文件分析
	echo -e "${YELLOW}正在检查被授权登录公钥信息[/root/.ssh/authorized_keys]:${NC}" 
	log_message "INFO" "正在检查被授权登录公钥信息"
	echo -e "${BLUE}[KNOW] authorized_keys文件是用于存储用户在远程登录时所被允许的公钥,可定位谁可以免密登陆该主机" 
	echo -e "${BLUE}[KNOW] 免密登录配置中需要将用户公钥内容追加到authorized_keys文件中[cat id_rsa.pub >> authorized_keys]"
	# log_message "INFO" "authorized_keys文件是用于存储用户在远程登录时所被允许的公钥,可定位谁可以免密登陆该主机"
	authkey=$(cat /root/.ssh/authorized_keys 2>/dev/null)
	if [ -n "$authkey" ];then
		echo -e "${RED}[WARN] 发现被授权登录的用户公钥信息如下${NC}" && echo "$authkey"
		log_message "WARN" "发现被授权登录的用户公钥信息"
	else
		echo -e "${GREEN}[SUCC] 未发现被授权登录的用户公钥信息${NC}" 
		log_message "INFO" "未发现被授权登录的用户公钥信息"
	fi
	printf "\n" 

	# known_hosts文件分析
	echo -e "${YELLOW}正在检查当前设备可登录主机信息[/root/.ssh/known_hosts]:${NC}" 
	log_message "INFO" "正在检查当前设备可登录主机信息"
	echo -e "${BLUE}[KNOW] known_hosts文件是用于存储SSH服务器公钥的文件,可用于排查当前主机可横向范围,快速定位可能感染的主机${NC}" 
	# log_message "INFO" "known_hosts文件是用于存储SSH服务器公钥的文件,可用于排查当前主机可横向范围,快速定位可能感染的主机"
	knownhosts=$(cat /root/.ssh/known_hosts 2>/dev/null | awk '{print $1}')
	if [ -n "$knownhosts" ];then
		echo -e "${RED}[WARN] 发现可横向远程主机信息如下:${NC}" && echo "$knownhosts"
		log_message "WARN" "发现可横向远程主机信息"
	else
		echo -e "${GREEN}[SUCC] 未发现可横向远程主机信息${NC}" 
		log_message "INFO" "未发现可横向远程主机信息"
	fi
	printf "\n" 


	# sshd_config 配置文件分析
	echo -e "${YELLOW}正在检查SSHD配置文件[/etc/ssh/sshd_config]:${NC}" 
	log_message "INFO" "正在检查SSHD配置文件"
	echo -e "${YELLOW}正在输出SSHD文件所有开启配置(不带#号的配置)[/etc/ssh/sshd_config]:"
	# log_message "INFO" "正在输出SSHD文件所有开启配置(不带#号的配置)"
	sshdconfig=$(cat /etc/ssh/sshd_config 2>/dev/null | egrep -v "#|^$")
	if [ $? -ne 0 ]; then
		handle_error 1 "读取/etc/ssh/sshd_config文件失败" "sshFileCheck"
	fi
	if [ -n "$sshdconfig" ];then
		echo -e "${YELLOW}[INFO] sshd_config所有开启的配置如下:${NC}" && echo "$sshdconfig" 
		log_message "INFO" "sshd_config所有开启的配置"
	else
		echo -e "${RED}[WARN] 未发现sshd_config开启任何配置!请留意这是异常现象!${NC}" 
		log_message "WARN" "未发现sshd_config开启任何配置!请留意这是异常现象!"
	fi
	printf "\n" 

	## sshd_config 配置文件分析 -- 允许空口令登录分析
	echo -e "${YELLOW}正在检查sshd_config配置--允许SSH空口令登录[/etc/ssh/sshd_config]:${NC}" 
	log_message "INFO" "正在检查sshd_config配置--允许SSH空口令登录"
	emptypasswd=$(cat /etc/ssh/sshd_config 2>/dev/null | grep -w "^PermitEmptyPasswords yes")
	nopasswd=$(awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null)
	if [ -n "$emptypasswd" ];then
		echo -e "${RED}[WARN] 发现允许空口令登录,请注意!${NC}"
		log_message "WARN" "发现允许空口令登录,请注意!"
		if [ -n "$nopasswd" ];then
			echo -e "${RED}[WARN] 以下用户空口令:${NC}" && echo "$nopasswd"
			log_message "WARN" "发现空口令用户"
		else
			echo -e "${GREEN}[SUCC] 未发现空口令用户${NC}" 
			log_message "INFO" "未发现空口令用户"
		fi
	else
		echo -e "${GREEN}[SUCC] 已关闭空口令用户登录${NC}" 
		log_message "INFO" "已关闭空口令用户登录"
	fi
	printf "\n" 

	## sshd_config 配置文件分析 -- root远程登录分析
	echo -e "${YELLOW}正在检查sshd_config配置--允许SSH远程root登录[/etc/ssh/sshd_config]:${NC}" 
	log_message "INFO" "正在检查sshd_config配置--允许SSH远程root登录"
	rootRemote=$(cat /etc/ssh/sshd_config 2>/dev/null | grep -v ^# | grep "PermitRootLogin yes")
	if [ -n "$rootRemote" ];then
		echo -e "${RED}[WARN] 发现允许root远程登录,请注意!${NC}"
		log_message "WARN" "发现允许root远程登录,请注意!"
		echo -e "${RED}[WARN] 请修改/etc/ssh/sshd_config配置文件,添加PermitRootLogin no${NC}"
		log_message "WARN" "请修改/etc/ssh/sshd_config配置文件,添加PermitRootLogin no"
	else
		echo -e "${GREEN}[SUCC] 已关闭root远程登录${NC}" 
		log_message "INFO" "已关闭root远程登录"
	fi
	printf "\n" 

	## sshd_config 配置文件分析 -- ssh协议版本分析
	echo -e "${YELLOW}正在检查sshd_config配置--检查SSH协议版本[/etc/ssh/sshd_config]:${NC}" 
	log_message "INFO" "正在检查sshd_config配置--检查SSH协议版本"
	echo -e "${BLUE}[KNOW] 需要详细的SSH版本信息另行检查,防止SSH协议版本过低,存在漏洞"
	echo -e "${BLUE}[KNOW] 从OpenSSH7.0开始,已经默认使用SSH协议2版本,只有上古机器这项会不合格${NC}"
	# log_message "INFO" "需要详细的SSH版本信息另行检查,防止SSH协议版本过低,存在漏洞"
	protocolver=$(cat /etc/ssh/sshd_config 2>/dev/null | grep -v ^$ | grep Protocol | awk '{print $2}')
	if [ -n "$protocolver" ];then
		echo -e "${YELLOW}[INFO] openssh协议版本如下:${NC}" && echo "$protocolver"
		log_message "INFO" "输出openssh协议版本信息"
		if [ "$protocolver" -eq "2" ];then
			echo -e "${YELLOW}[INFO] openssh使用ssh2协议,版本过低!${NC}" 
			log_message "WARN" "openssh使用ssh2协议,版本过低!"
		fi
	else
		echo -e "${YELLOW}[INFO] 未发现openssh协议版本(未发现并非代表异常)${NC}"
		log_message "INFO" "未发现openssh协议版本(未发现并非代表异常)"
	fi

	# ssh版本分析 -- 罗列几个有漏洞的ssh版本
	echo -e "${YELLOW}正在检查SSH版本[ssh -V]:${NC}"
	log_message "INFO" "正在检查SSH版本"
	sshver=$(ssh -V 2>&1)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取SSH版本信息失败" "sshFileCheck"
	fi
	echo -e "${YELLOW}[INFO] ssh版本信息如下:${NC}" && echo "$sshver"
	log_message "INFO" "ssh版本信息"

	# 记录性能统计和操作完成
	end_time=$(date +%s)
	log_performance "sshFileCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - SSHFILECHECK" "SSH文件配置检查模块执行完成" "END"

	# 上述光检测了root账户下的相关文件的信息,需要增加机器上其他账号的相关文件检测,比如/home/test/.ssh/authorized_keys 等文件 --- 20250708
	# 其他
}


# 检查最近变动文件的函数 
checkRecentModifiedFiles() {
	# 功能: 检查指定时间范围内变动的文件,支持敏感文件和所有文件两种模式
	# 参数1: 时间范围(小时数,默认24)
	# 参数2: 检查类型(sensitive|all,默认sensitive)
	# 使用示例:
	#   checkRecentModifiedFiles                    # 检查最近24小时内的敏感文件
	#   checkRecentModifiedFiles 48                 # 检查最近48小时内的敏感文件
	#   checkRecentModifiedFiles 24 "sensitive"     # 检查最近24小时内的敏感文件
	#   checkRecentModifiedFiles 24 "all"          # 检查最近24小时内的所有文件
	local time_hours=${1:-24}  # 默认24小时
	local check_type=${2:-"sensitive"}  # 默认检查敏感文件
	
	echo -e "${YELLOW}正在检查最近${time_hours}小时内变动的文件:${NC}"
	
	# 定义排除目录列表
	local EXCLUDE_DIRS=(
		"/proc/*"
		"/dev/*"
		"/sys/*"
		"/run/*"
		"/tmp/systemd-private-*"
		"*/node_modules/*"
		"*/.cache/*"
		"*/site-packages/*"
		"*/.vscode-server/*"
		"*/cache/*"
		"*.log"
	)
	
	# 定义敏感文件后缀列表
	local SENSITIVE_EXTENSIONS=(
		"*.py"
		"*.sh"
		"*.per"
		"*.pl"
		"*.php"
		"*.asp"
		"*.jsp"
		"*.exe"
		"*.jar"
		"*.war"
		"*.class"
		"*.so"
		"*.elf"
		"*.txt"
	)
	
	# 计算mtime参数 (小时转换为天数的分数)
	local mtime_param
	if [ "$time_hours" -le 24 ]; then
		mtime_param="-1"  # 24小时内
	else
		local days=$((time_hours / 24))
		mtime_param="-${days}"
	fi
	
	# 构建find命令的排除条件
	local exclude_conditions=()
	for exclude_dir in "${EXCLUDE_DIRS[@]}"; do
		exclude_conditions+=("-not" "-path" "$exclude_dir")
	done
	
	if [ "$check_type" = "sensitive" ]; then
		echo -e "${YELLOW}[KNOW] 检查敏感文件类型: ${SENSITIVE_EXTENSIONS[*]}${NC}"
		echo -e "${YELLOW}[NOTE] 排除目录: ${EXCLUDE_DIRS[*]}${NC}"
		
		# 构建文件扩展名条件
		local extension_conditions=()
		for i in "${!SENSITIVE_EXTENSIONS[@]}"; do
			extension_conditions+=("-name" "${SENSITIVE_EXTENSIONS[$i]}")
			if [ $i -lt $((${#SENSITIVE_EXTENSIONS[@]}-1)) ]; then
				extension_conditions+=("-o")
			fi
		done
		
		# 执行find命令查找敏感文件
		local find_result
		find_result=$(find / "${exclude_conditions[@]}" -mtime "$mtime_param" -type f \( "${extension_conditions[@]}" \) 2>/dev/null)
		
		if [ -n "$find_result" ]; then
			echo -e "${RED}[WARN] 发现最近${time_hours}小时内变动的敏感文件:${NC}"
			echo "$find_result"
		else
			echo -e "${GREEN}[SUCC] 未发现最近${time_hours}小时内变动的敏感文件${NC}"
		fi
		
	elif [ "$check_type" = "all" ]; then
		echo -e "${YELLOW}[KNOW] 检查所有文件类型${NC}"
		echo -e "${YELLOW}[NOTE] 排除目录: ${EXCLUDE_DIRS[*]}${NC}"
		
		# 执行find命令查找所有文件
		local find_result_all
		find_result_all=$(find / "${exclude_conditions[@]}" -type f -mtime "$mtime_param" 2>/dev/null)
		
		if [ -n "$find_result_all" ]; then
			echo -e "${RED}[WARN] 发现最近${time_hours}小时内变动的所有文件:${NC}"
			echo "$find_result_all"
		else
			echo -e "${GREEN}[SUCC] 未发现最近${time_hours}小时内变动的文件${NC}"
		fi
	else
		echo -e "${RED}[WARN] 错误: 不支持的检查类型 '$check_type',支持的类型: sensitive, all${NC}"
		return 1
	fi
	
	printf "\n"
}


# 特殊文件排查【归档 -- fileCheck】
specialFileCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - SPECIALFILECHECK" "特殊文件检查模块" "START"
	
	# SSH相关文件排查 -- 调用检查函数 sshFileCheck
	echo -e "${YELLOW}[INFO] 正在检查SSH相关文件[Fuc:sshFileCheck]:${NC}"
	log_message "INFO" "正在检查SSH相关文件"
	sshFileCheck
	
	# 环境变量分析
	echo -e "${YELLOW}[INFO] 正在检查环境变量文件[.bashrc|.bash_profile|.zshrc|.viminfo等]:${NC}" 
	echo -e "${YELLOW}[KNOW] 环境变量文件是用于存放用户环境变量的文件,可用于后门维持留马等(需要人工检查有无权限维持痕迹)${NC}" 
	env_file="/root/.bashrc /root/.bash_profile /root/.zshrc /root/.viminfo /etc/profile /etc/bashrc /etc/environment"
	for file in $env_file;do
		if [ -e $file ];then
			echo -e "${YELLOW}[INFO] 环境变量文件:$file${NC}"
			log_message "INFO" "检查环境变量文件:$file"
			more $file 2>/dev/null
			if [ $? -ne 0 ]; then
				handle_error 1 "读取环境变量文件失败:$file" "specialFileCheck"
			fi
			printf "\n"
			# 文件内容中是否包含关键字 curl http https wget 等关键字
			suspicious_content=$(more $file 2>/dev/null | grep -E "curl|wget|http|https|python")
			if [ -n "$suspicious_content" ];then
				echo -e "${RED}[WARN] 发现环境变量文件[$file]中包含curl|wget|http|https|python等关键字!${NC}" 
			fi 
		else
			echo -e "${YELLOW}[INFO] 未发现环境变量文件:$file${NC}"
		fi
	done
	printf "\n"

	## 环境变量env命令分析
	echo -e "${YELLOW}[INFO] 正在检查环境变量命令[env]:${NC}"
	env_tmp=$(env)
	if [ -n "$env_tmp" ];then
		echo -e "${YELLOW}[INFO] 环境变量命令结果如下:${NC}" && echo "$env_tmp"
	else
		echo -e "${RED}[WARN] 未发现环境变量命令结果${NC}"
	fi
	
	# 【新增】正在运行进程的环境变量检查 (来自LinuxCheck.sh)
	echo -e "${YELLOW}[INFO] 正在检查运行进程的环境变量问题:${NC}"
	log_message "INFO" "正在检查运行进程的环境变量问题" "specialFileCheck"
	
	local proc_env_check=$(grep -P 'LD_PRELOAD|LD_ELF_PRELOAD|LD_AOUT_PRELOAD|PROMPT_COMMAND|LD_LIBRARY_PATH' /proc/*/environ 2>/dev/null)
	if [[ -n "$proc_env_check" ]]; then
		echo -e "${RED}[WARN] 发现进程环境变量异常:${NC}"
		echo "$proc_env_check" | while read -r line; do
			echo -e "${RED}[WARN] $line${NC}"
			log_message "WARN" "进程环境变量异常: $line" "specialFileCheck"
		done
	else
		echo -e "${GREEN}[SUCC] 进程环境变量检查通过${NC}"
		log_message "INFO" "进程环境变量检查通过" "specialFileCheck"
	fi
	printf "\n"

	# hosts文件分析
	echo -e "${YELLOW}[INFO] 正在检查hosts文件[/etc/hosts]:${NC}"
	hosts_tmp=$(cat /etc/hosts)
	if [ -n "$hosts_tmp" ];then
		echo -e "${YELLOW}[INFO] hosts文件如下:${NC}" && echo "$hosts_tmp"
	else
		echo -e "${RED}[WARN] 未发现hosts文件${NC}"
	fi
	printf "\n"

	# shadow文件分析
	echo -e "${YELLOW}[INFO] 正在检查shadow文件[/etc/shadow]:${NC}"
	shadow_tmp=$(cat /etc/shadow)
	if [ -n "$shadow_tmp" ];then
		# 输出 shadow 文件内容
		echo -e "${YELLOW}[INFO] shadow文件如下:${NC}" && echo "$shadow_tmp"
	else
		echo -e "${RED}[WARN] 未发现shadow文件${NC}"
	fi
	printf "\n"

	## gshadow文件分析
	echo -e "${YELLOW}[INFO] 正在检查gshadow文件[/etc/gshadow]:${NC}"
	gshadow_tmp=$(cat /etc/gshadow)
	if [ -n "$gshadow_tmp" ];then
		# 输出 gshadow 文件内容
		echo -e "${YELLOW}[INFO] gshadow文件如下:${NC}" && echo "$gshadow_tmp"
	else
		echo -e "${RED}[WARN] 未发现gshadow文件${NC}"
	fi
	printf "\n"

	# 24小时内修改文件分析 - 使用新的函数checkRecentModifiedFiles
	echo -e "${YELLOW}[INFO] 正在检查最近变动的文件(默认24小时内新增/修改):${NC}"
	# 检查敏感文件(默认24小时)
	checkRecentModifiedFiles 24 "sensitive"
	# 检查所有文件(默认24小时)
	checkRecentModifiedFiles 24 "all"

	# SUID/SGID Files 可用于提权 
	## SUID(Set User ID) 文件是一种特殊权限文件,它允许文件拥有者以root权限运行,而不需要root权限。
	## SGID(Set Group ID) 文件是一种特殊权限文件,任何用户运行该文件时都会以文件所属组的权限执行,对于目录,SGID目录下创建的文件会继承该组的权限。
	echo -e "${YELLOW}[INFO] 正在检查SUID/SGID文件:${NC}"
	echo -e "${YELLOW}[NOTE]如果SUID/SGID文件同时出现在最近24H变换检测中,说明机器有极大概率已经中招${NC}"
	find_suid=$(find / -type f -perm -4000)
	if [ -n "$find_suid" ];then
		echo -e "${YELLOW}[INFO] SUID文件如下:${NC}" && echo "$find_suid"
	fi

	find_sgid=$(find / -type f -perm -2000)
	if [ -n "$find_sgid" ];then
		echo -e "${YELLOW}[INFO] SGID文件如下:${NC}" && echo "$find_sgid"
	fi

	# 其他
}

# 系统日志分析【归档 -- fileCheck】
systemLogCheck(){
	# 1 系统有哪些日志类型 [ls /var/log/]
	echo -e "${YELLOW}[INFO] 正在查看系统存在哪些日志文件[ls /var/log]:${NC}"
	# 获取 /var/log 目录下的日志文件列表
	allLog=$(ls /var/log 2>/dev/null)
	# 检查是否成功获取到日志文件列表
	if [ -n "$allLog" ]; then
		echo -e "${YELLOW}[INFO] 系统存在以下日志文件:${NC}"
		echo "$allLog" | while read -r logFile; do
			echo "- $logFile"
		done
	else
		echo -e "${RED}[WARN] 未找到任何日志文件或无法访问 /var/log 目录,日志目录有可能被删除! ${NC}"
	fi
	printf "\n"

	# 2 message日志分析 [系统消息日志] 排查第一站 【ubuntu系统是/var/log/syslog】
	echo -e "${YELLOW}正在分析系统消息日志[message]:${NC}"
	## 检查传输文件情况
	echo -e "${YELLOW}正在检查是否使用ZMODEM协议传输文件[more /var/log/message* | grep "ZMODEM:.*BPS"]:" 
	zmodem=$(more /var/log/message* | grep "ZMODEM:.*BPS")
	if [ -n "$zmodem" ];then
		(echo -e "${RED}[WARN] 传输文件情况:${NC}" && echo "$zmodem") 
	else
		echo -e "${GREEN}[SUCC] 日志中未发现传输文件${NC}" 
	fi
	printf "\n" 

	## 2.1 检查DNS服务器使用情况
	echo -e "${YELLOW}正在检查日志中该机器使用DNS服务器的情况[/var/log/message* |grep "using nameserver"]:" 
	dns_history=$(more /var/log/messages* | grep "using nameserver" | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
	if [ -n "$dns_history" ];then
		(echo -e "${RED}[WARN] 该服务器曾经使用以下DNS服务器(需要人工判断DNS服务器是否涉黑,不涉黑可以忽略):${NC}" && echo "$dns_history") 
	else
		echo -e "${YELLOW}[INFO] 未发现该服务器使用DNS服务器${NC}" 
	fi
	printf "\n"


	# 3 secure日志分析 [安全认证和授权日志] [ubuntu等是auth.log]
	## 智能系统兼容 - 优化版 (结合Whoamifuck优点)
	echo -e "${BLUE}[INFO]${NC} 开始智能安全日志分析..."
	log_message "INFO" "开始安全日志分析"
	
	# 判断系统类型并选择正确的日志文件
	AUTH_LOG=""
	if [ -f /var/log/auth.log ]; then
		AUTH_LOG="/var/log/auth.log"
		echo -e "${GREEN}[SUCC]${NC} 检测到Ubuntu/Debian系统，使用auth.log"
		log_message "INFO" "检测到Ubuntu/Debian系统，使用auth.log"
	elif [ -f /var/log/secure ]; then
		AUTH_LOG="/var/log/secure"
		echo -e "${GREEN}[SUCC]${NC} 检测到CentOS/RHEL系统，使用secure日志"
		log_message "INFO" "检测到CentOS/RHEL系统，使用secure日志"
	else
		echo -e "${RED}[WARN]${NC} 无法找到系统安全日志文件（auth.log 或 secure）"
		log_message "WARN" "无法找到系统安全日志文件"
		AUTH_LOG=""
	fi

	if [ -n "$AUTH_LOG" ]; then
		echo -e "${YELLOW}[3.0]正在检查系统安全日志中登录成功记录[grep 'Accepted' ${AUTH_LOG}*]:${NC}"

		# 增强版登录成功分析 (借鉴Whoamifuck的分析方法)
		loginsuccess=$(grep "Accepted" "${AUTH_LOG}"* 2>/dev/null)
		if [ -n "$loginsuccess" ]; then
			echo -e "${YELLOW}[INFO]${NC} 日志中分析到以下用户登录成功记录:"
			echo "$loginsuccess" | tail -10  # 只显示最近10条
			
			echo -e "${YELLOW}[INFO]${NC} 登录成功的IP统计(按次数排序):"
			grep "Accepted" "${AUTH_LOG}"* 2>/dev/null | awk '{print $11}' | sort | uniq -c | sort -rn | head -10 | while read count ip; do
				echo -e "  ${GREEN}→${NC} $ip (登录 $count 次)"
			done
			
			echo -e "${YELLOW}[INFO]${NC} 登录成功的用户统计(按次数排序):"
			grep "Accepted" "${AUTH_LOG}"* 2>/dev/null | awk '{print $9}' | sort | uniq -c | sort -rn | head -10 | while read count user; do
				echo -e "  ${GREEN}→${NC} $user (登录 $count 次)"
			done
			
			# 新增：最近登录时间分析
			echo -e "${YELLOW}[INFO]${NC} 最近登录时间分析:"
			grep "Accepted" "${AUTH_LOG}"* 2>/dev/null | tail -5 | awk '{print $1"-"$2"-"$3, "用户:"$9, "来源:"$11, "方式:"$7}' | while read line; do
				echo -e "  ${BLUE}→${NC} $line"
			done
			
			log_message "INFO" "登录成功分析完成，发现$(echo "$loginsuccess" | wc -l)条记录"
		else
			echo -e "${GREEN}[SUCC]${NC} 日志中未发现成功登录的情况"
			log_message "INFO" "日志中未发现成功登录记录"
		fi
	else
		echo -e "${YELLOW}[NOTE]${NC} 跳过安全日志分析：未找到可用的日志文件"
		log_message "INFO" "跳过安全日志分析：未找到可用的日志文件"
	fi
	printf "\n"


	echo -e "${YELLOW}正在分析系统安全日志[secure]:${NC}"
	## SSH安全日志分析
	echo -e "${YELLOW}正在检查系统安全日志中登录成功记录[more /var/log/secure* | grep "Accepted" ]:${NC}" 
	# loginsuccess=$(more /var/log/secure* | grep "Accepted password" | awk '{print $1,$2,$3,$9,$11}')
	loginsuccess=$(more /var/log/secure* | grep "Accepted" )  # 获取日志中登录成功的记录 包括 密码认证和公钥认证
	if [ -n "$loginsuccess" ];then
		(echo -e "${YELLOW}[INFO] 日志中分析到以下用户登录成功记录:${NC}" && echo "$loginsuccess")  
		(echo -e "${YELLOW}[INFO] 登录成功的IP及次数如下:${NC}" && grep "Accepted " /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c )  
		(echo -e "${YELLOW}[INFO] 登录成功的用户及次数如下:${NC}" && grep "Accepted" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c )  
	else
		echo "[INFO] 日志中未发现成功登录的情况" 
	fi
	printf "\n" 

	## 3.1 SSH爆破情况分析 (增强版 - 结合Whoamifuck分析方法)
	echo -e "${YELLOW}[3.1]正在检查SSH暴力破解攻击[Failed password]:${NC}"
	log_message "INFO" "开始SSH暴力破解分析"
	
	# 使用智能日志文件选择
	local target_log="${AUTH_LOG:-/var/log/secure}"
	loginfailed=$(grep "Failed" "${target_log}"* 2>/dev/null)
	
	if [ -n "$loginfailed" ]; then
		echo -e "${RED}[WARN]${NC} 发现SSH登录失败记录，正在分析..."
		
		# 1. TOP攻击IP统计 (借鉴Whoamifuck的展示方式)
		echo -e "${RED}[WARN]${NC} SSH暴力破解TOP攻击IP:"
		grep "Failed" "${target_log}"* 2>/dev/null | awk 'match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {print substr($0, RSTART, RLENGTH)}' | sort | uniq -c | sort -rn | head -10 | while read count ip; do
			if [ "$count" -gt 10 ]; then
				echo -e "  ${RED}→${NC} $ip (攻击 $count 次) ${RED}[高危]${NC}"
			elif [ "$count" -gt 3 ]; then
				echo -e "  ${YELLOW}→${NC} $ip (攻击 $count 次) ${YELLOW}[中危]${NC}"
			else
				echo -e "  ${BLUE}→${NC} $ip (攻击 $count 次) ${BLUE}[低危]${NC}"
			fi
		done
		
		# 2. 攻击目标用户分析 (区分有效用户和无效用户)
		echo -e "${RED}[WARN]${NC} SSH暴力破解目标用户分析:"
		echo -e "${YELLOW}  有效用户被攻击情况:${NC}"
		grep "Failed" "${target_log}"* 2>/dev/null | grep -v "invalid user" | awk '/Failed/ {for_index = index($0, "for ") + 4; from_index = index($0, " from "); user = substr($0, for_index, from_index - for_index); print user}' | sort | uniq -c | sort -rn | head -5 | while read count user; do
			echo -e "    ${RED}→${NC} $user (被攻击 $count 次)"
		done
		
		echo -e "${YELLOW}  无效用户枚举情况:${NC}"
		grep "Failed" "${target_log}"* 2>/dev/null | grep "invalid user" | awk '/Failed/ {for_index = index($0, "invalid user ") + 13; from_index = index($0, " from "); user = substr($0, for_index, from_index - for_index); print user}' | sort | uniq -c | sort -rn | head -5 | while read count user; do
			echo -e "    ${BLUE}→${NC} $user (枚举 $count 次)"
		done
		
		# 3. 攻击时间分析
		echo -e "${YELLOW}[INFO]${NC} 最近攻击时间分析:"
		grep "Failed" "${target_log}"* 2>/dev/null | tail -5 | awk '{print $1"-"$2"-"$3, "攻击目标:", ($9 == "invalid" ? $11 : $9), "来源:", (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) ? substr($0, RSTART, RLENGTH) : "未知")}' | while read line; do
			echo -e "  ${RED}→${NC} $line"
		done
		
		# 统计信息
		local total_failed=$(echo "$loginfailed" | wc -l)
		local unique_ips=$(grep "Failed" "${target_log}"* 2>/dev/null | awk 'match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {print substr($0, RSTART, RLENGTH)}' | sort -u | wc -l)
		echo -e "${YELLOW}[统计]${NC} 总计失败登录 $total_failed 次，涉及 $unique_ips 个不同IP"
		log_message "WARN" "发现SSH暴力破解：总计$total_failed次失败登录，涉及$unique_ips个IP"
		
	else
		echo -e "${GREEN}[SUCC]${NC} 日志中未发现登录失败记录"
		log_message "INFO" "未发现SSH登录失败记录"
	fi
	printf "\n" 

	## 3.2 本机SSH登录成功并建立会话的日志记录
	echo -e "${YELLOW}正在检查本机SSH成功登录记录[more /var/log/secure* | grep -E "sshd:session.*session opened" ]:${NC}" 
	systemlogin=$(more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
	if [ -n "$systemlogin" ];then
		(echo -e "${YELLOW}[INFO] 本机SSH成功登录情况:${NC}" && echo "$systemlogin") 
		(echo -e "${YELLOW}[INFO] 本机SSH成功登录账号及次数如下:${NC}" && more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c) 
	else
		echo -e "${RED}[WARN] 未发现在本机登录退出情况,请注意!${NC}" 
	fi
	printf "\n" 

	## 3.3 检查新增用户
	echo -e "${YELLOW}正在检查新增用户[more /var/log/secure* | grep "new user"]:${NC}"
	newusers=$(more /var/log/secure* | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
	if [ -n "$newusers" ];then
		(echo -e "${RED}[WARN] 日志中发现新增用户:${NC}" && echo "$newusers") 
		(echo -e "${YELLOW}[INFO] 新增用户账号及次数如下:${NC}" && more /var/log/secure* | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) 
	else
		echo -e "${GREEN}[SUCC] 日志中未发现新增加用户${NC}" 
	fi
	printf "\n" 

	## 3.4 检查新增用户组
	echo -e "${YELLOW}正在检查新增用户组[/more /var/log/secure* | grep "new group"]:${NC}" 
	newgoup=$(more /var/log/secure* | grep "new group"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
	if [ -n "$newgoup" ];then
		(echo -e "${RED}[WARN] 日志中发现新增用户组:${NC}" && echo "$newgoup") 
		(echo -e "${YELLOW}[INFO] 新增用户组及次数如下:${NC}" && more /var/log/secure* | grep "new group" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) 
	else
		echo -e "${GREEN}[SUCC] 日志中未发现新增加用户组${NC}" 
	fi
	printf "\n" 


	# 4 计划任务日志分析 cron日志分析 [cron作业调度器日志]
	echo -e "${YELLOW}正在分析cron日志:${NC}" 
	echo -e "${YELLOW}正在分析定时下载[/var/log/cron*]:${NC}" 
	cron_download=$(more /var/log/cron* | grep "wget|curl")
	if [ -n "$cron_download" ];then
		(echo -e "${RED}[WARN] 定时下载情况:${NC}" && echo "$cron_download") 
	else
		echo -e "${GREEN}[SUCC] 未发现定时下载情况${NC}" 
	fi
	printf "\n" 

	echo -e "${YELLOW}正在分析定时执行脚本[/var/log/cron*]:${NC}" 
	cron_shell=$(more /var/log/cron* | grep -E "\.py$|\.sh$|\.pl$|\.exe$") 
	if [ -n "$cron_shell" ];then
		(echo -e "${RED}[WARN] 发现定时执行脚本:${NC}" && echo "$cron_download") 
		echo -e "${GREEN}[SUCC] 未发现定时下载脚本${NC}" 
	fi
	printf "\n" 

	# 5 yum 日志分析 【只适配使用 yum 的系统,apt/history.log 的格式和yum 的格式差距较大,还有 dnf 包管理工具也另说】
	echo -e "${YELLOW}正在分析使用yum下载安装过的脚本文件[/var/log/yum*|grep Installed]:${NC}"  
	yum_installscripts=$(more /var/log/yum* | grep Installed | grep -E "(\.sh$\.py$|\.pl$|\.exe$)" | awk '{print $NF}' | sort | uniq)
	if [ -n "$yum_installscripts" ];then
		(echo -e "${RED}[WARN] 曾使用yum下载安装过以下脚本文件:${NC}"  && echo "$yum_installscripts")  
	else
		echo -e "${GREEN}[SUCC] 未发现使用yum下载安装过脚本文件${NC}"  
	fi
	printf "\n"  


	echo -e "${YELLOW}正在检查使用yum卸载软件情况[/var/log/yum*|grep Erased]:${NC}" 
	yum_erased=$(more /var/log/yum* | grep Erased)
	if [ -n "$yum_erased" ];then
		(echo -e "${YELLOW}[INFO] 使用yum曾卸载以下软件:${NC}" && echo "$yum_erased")  
	else
		echo -e "${YELLOW}[INFO] 未使用yum卸载过软件${NC}"  
	fi
	printf "\n"  

	echo -e "${YELLOW}正在检查使用yum安装的可疑工具[./checkrules/hackertoolslist.txt]:"  
	# 从文件中取出一个工具名然后匹配
	hacker_tools_list=$(cat ./checkrules/hackertoolslist.txt)
	for hacker_tools in $hacker_tools_list;do
		hacker_tools=$(more /var/log/yum* | awk -F: '{print $NF}' | awk -F '[-]' '{print }' | sort | uniq | grep -E "$hacker_tools")
		if [ -n "$hacker_tools" ];then
			(echo -e "${RED}[WARN] 发现使用yum下载过以下可疑软件:${NC}"&& echo "$hacker_tools")  
		else
			echo -e "${GREEN}[SUCC] 未发现使用yum下载过可疑软件${NC}"  
		fi
	done
	printf "\n"  

	
	# 6 dmesg日志分析 [内核环境提示信息,包括启动消息、硬件检测和系统错误]
	echo -e "${YELLOW}正在分析dmesg内核自检日志[dmesg]:${NC}" 
	dmesg=$(dmesg)
	if [ $? -eq 0 ];then
		(echo -e "${YELLOW}[INFO] 日志自检日志如下:${NC}" && echo "$dmesg" ) 
	else
		echo -e "${RED}[WARN] 未发现内核自检日志${NC}" 
	fi
	printf "\n" 


	# 7 btmp 日志分析 [记录失败的登录尝试,包括日期、时间和用户名] 【二进制日志文件,不能直接 cat 查看】
	echo -e "正在分析btmp错误登录日志[lastb]:"  
	lastb=$(lastb)
	if [ -n "$lastb" ];then
		(echo -e "${YELLOW}[INFO] 错误登录日志如下:${NC}" && echo "$lastb") 
	else
		echo -e "${RED}[WARN] 未发现错误登录日志${NC}"  
	fi
	printf "\n"  

	# 8 lastlog 日志分析 [记录最后一次登录的日志,包括日期、时间和用户名]
	echo -e "[14.8]正在分析lastlog最后一次登录日志[lastlog]:"  
	lastlog=$(lastlog)
	if [ -n "$lastlog" ];then
		(echo -e "${YELLOW}[INFO] 所有用户最后一次登录日志如下:${NC}" && echo "$lastlog")  
	else
		echo -e "${RED}[WARN] 未发现所有用户最后一次登录日志${NC}"  
	fi
	printf "\n"  


	# 9 wtmp日志分析 [记录系统关闭、重启和登录/注销事件]
	# 【grep 排除 :0 登录,这个是图形化登录】
	echo -e "${YELLOW}正在分析wtmp日志[last | grep pts | grep -vw :0]:${NC}"  
	echo -e "${YELLOW}正在检查历史上登录到本机的用户(非图形化UI登录):${NC}"  
	lasts=$(last | grep pts | grep -vw :0)
	if [ -n "$lasts" ];then
		(echo -e "${YELLOW}[INFO] 历史上登录到本机的用户如下:${NC}" && echo "$lasts")  
	else
		echo -e "${RED}[WARN] 未发现历史上登录到本机的用户信息${NC}"  
	fi
	printf "\n"  


	# 10 journalctl 日志分析
	# journalctl 的使用方法
	# -u 显示指定服务日志 journalctl -u sshd.service
	# -f 显示实时日志 journalctl -f
	# -k 显示内核环缓冲区中的消息 journalctl -k 
	# -p 显示指定优先级日志 journalctl -p err [emerg、alert、crit、err、warning、notice、info、debug]
	# -o  指定输出格式 journalctl -o json-pretty > logs.json
	echo -e "${YELLOW}正在使用journalctl分析日志:${NC}"  
	# 检查最近24小时内的journalctl日志
	echo -e "${YELLOW}正在检查最近24小时内的日志[journalctl --since "24 hours ago"]:${NC}"  
	journalctl=$(journalctl --since "24 hours ago")
	if [ -n "$journalctl" ];then
		echo -e "${YELLOW}[INFO] journalctl最近24小时内的日志输出到[$log_file/journalctl_24h.txt]:${NC}"  
		echo "$journalctl" >> $log_file/journalctl_24H.txt
	else
		echo -e "${RED}[WARN] journalctl未发现最近24小时内的日志${NC}"  
	fi
	printf "\n"
	echo -e "${YELLOW}journalctl 其他使用参数:${NC}"
	echo -e "${YELLOW} -u 显示指定服务日志[journalctl -u sshd.service]${NC}"
	echo -e "${YELLOW} -f 显示实时日志[journalctl -f]${NC}"
	echo -e "${YELLOW} -k 显示内核环缓冲区中的消息[journalctl -k]${NC}"
	echo -e "${YELLOW} -p 显示指定优先级日志[journalctl -p err] [emerg、alert、crit、err、warning、notice、info、debug]${NC}"
	echo -e "${YELLOW} -o 指定输出格式[journalctl -o json-pretty > logs.json]${NC}"
	printf "\n"  

	# 11 auditd 服务状态分析
	echo -e "正在分析日志审核服务是否开启[systemctl status auditd.service]:" 
	# auditd=$(systemctl status auditd.service | grep running)
	auditd=$(systemctl status auditd.service | head  -n 12)
	# if [ $? -eq 0 ];then
	# 	echo "[INFO] 系统日志审核功能已开启,符合要求" 
	# else
	# 	echo "[WARN] 系统日志审核功能已关闭,不符合要求,建议开启日志审核。可使用以下命令开启:service auditd start" 
	# fi
	if [ -n "$auditd" ];then
		(echo -e "${YELLOW}[INFO] auditd服务信息如下:${NC}" && echo "$auditd")  
	fi
	printf "\n" 

	# 12 rsyslog 日志主配置文件
	echo -e "${YELLOW}正在检查rsyslog主配置文件[/etc/rsyslog.conf]:"  
	logconf=$(more /etc/rsyslog.conf | egrep -v "#|^$")
	if [ -n "$logconf" ];then
		(echo -e "${YELLOW}[INFO] 日志配置如下:${NC}" && echo "$logconf")  
	else
		echo -e "${RED}[WARN] 未发现日志配置文件${NC}"  
	fi
	printf "\n"  

}

# 文件信息排查【完成】
fileCheck(){
	# 系统服务排查 
	systemServiceCheck
	# 敏感目录排查 | 隐藏文件排查 dirFileCheck
	dirFileCheck
	# 特殊文件排查 [SSH相关文件|环境变量相关|hosts文件|shadow文件|24H变动文件|特权文件] sshCheck | specialFileCheck
	specialFileCheck
	# 日志文件分析 [message日志|secure日志分析|计划任务日志分析|yum日志分析 等日志] systemLogCheck 【重点】
	systemLogCheck
}

# 后门排查 【重构完成 - 统一后门检测入口】
backdoorCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - BACKDOOR" "统一后门检测模块" "START"
	
	echo -e "${GREEN}[SUCC]${NC} 统一后门检测模块开始执行"
	echo -e "${BLUE}[INFO]${NC} 检测类型: 进程后门、文件后门、权限后门、持久化后门、网络后门"
	echo ""
	
	# 1. 进程后门检测 (调用增强型进程检测中的后门部分)
	backdoor_process_check
	
	# 2. 文件系统后门检测 (调用特殊文件检测)
	backdoor_file_check
	
	# 3. 权限提升后门检测 (SUID/SGID)
	backdoor_privilege_check
	
	# 4. 持久化后门检测 (启动项/服务/定时任务)
	backdoor_persistence_check
	
	# 5. 网络后门检测 (SSH隧道/监听端口)
	backdoor_network_check
	
	# 6. 二进制文件时间戳检测 (新增功能)
	backdoor_timestamp_check
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - BACKDOOR" "统一后门检测模块" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} 统一后门检测模块执行完成"
	printf "\n"
}

# 后门进程检测 (整合现有功能)
backdoor_process_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查后门进程..."
	
	# 检查已知后门进程特征
	local backdoor_processes=(
		# 常见后门程序
		"nc\.traditional" "ncat" "socat" "netcat" "backdoor"
		"gh0st" "poison" "pcshare" "gray" "htran" "lcx"
		# 反弹shell相关
		"bash.*-i" "sh.*-i" "/dev/tcp" "/dev/udp"
		# 隐藏进程特征
		"\\[.*\\]" "\\s+$" "^\\s*$"
	)
	
	local backdoor_found=0
	for pattern in "${backdoor_processes[@]}"; do
		local suspicious_procs=$(ps aux | grep -v grep | grep -i -E "$pattern")
		if [[ -n "$suspicious_procs" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑后门进程 ($pattern):"
			echo "$suspicious_procs" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "发现后门进程: $proc" "backdoorCheck"
				((backdoor_found++))
			done
		fi
	done
	
	if [[ $backdoor_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的后门进程特征"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $backdoor_found 个可疑后门进程"
	fi
}

# 后门文件检测 (整合现有功能)
backdoor_file_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查后门文件..."
	
	# 常见后门文件路径和名称
	local backdoor_paths=("/tmp" "/var/tmp" "/dev/shm" "/usr/bin" "/usr/sbin" "/bin" "/sbin")
	local backdoor_files=(
		# 常见后门文件名
		".*backdoor.*" ".*trojan.*" ".*rootkit.*"
		".*\\.hide.*" ".*\\.ghost.*" ".*\\.evil.*"
		# 可疑脚本文件
		".*\\.sh$" ".*\\.pl$" ".*\\.py$" ".*\\.php$"
	)
	
	local files_found=0
	for path in "${backdoor_paths[@]}"; do
		if [[ -d "$path" ]]; then
			echo -e "${YELLOW}[检查路径]${NC} $path"
			
			# 检查最近7天修改的可执行文件
			local recent_executables=$(find "$path" -type f -executable -mtime -7 2>/dev/null)
			if [[ -n "$recent_executables" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 7天内修改的可执行文件:"
				echo "$recent_executables" | while read -r file; do
					local size=$(du -h "$file" 2>/dev/null | cut -f1)
					local mtime=$(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null)
					echo -e "  ${YELLOW}→${NC} $file ($size, $mtime)"
					((files_found++))
				done
			fi
			
			# 检查隐藏的可执行文件
			local hidden_executables=$(find "$path" -type f -name ".*" -executable 2>/dev/null)
			if [[ -n "$hidden_executables" ]]; then
				echo -e "${RED}[WARN]${NC} 隐藏的可执行文件:"
				echo "$hidden_executables" | while read -r file; do
					local size=$(du -h "$file" 2>/dev/null | cut -f1)
					echo -e "  ${RED}→${NC} $file ($size)"
					log_message "WARN" "发现隐藏后门文件: $file" "backdoorCheck"
					((files_found++))
				done
			fi
		fi
	done
	
	if [[ $files_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现可疑的后门文件"
	else
		echo -e "${RED}[WARN]${NC} 发现 $files_found 个可疑文件，建议进一步调查"
	fi
}

# 后门权限检测 (调用现有SUID检测)
backdoor_privilege_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查权限提升后门..."
	
	# 检查异常的SUID/SGID文件
	local suspicious_suid=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E "(sudo|passwd|su|ping|mount|umount|ssh|newgrp|chfn|chsh|gpasswd)" | head -20)
	if [[ -n "$suspicious_suid" ]]; then
		echo -e "${RED}[WARN]${NC} 发现可疑的SUID文件:"
		echo "$suspicious_suid" | while read -r suid_file; do
			local file_time=$(stat -c %y "$suid_file" 2>/dev/null || stat -f %Sm "$suid_file" 2>/dev/null)
			echo -e "  ${RED}→${NC} $suid_file ($file_time)"
			log_message "WARN" "发现可疑SUID后门: $suid_file" "backdoorCheck"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} SUID文件检查正常"
	fi
	
	local suspicious_sgid=$(find / -perm -2000 -type f 2>/dev/null | grep -v -E "(write|wall|locate|ssh)" | head -10)
	if [[ -n "$suspicious_sgid" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现可疑的SGID文件:"
		echo "$suspicious_sgid" | while read -r sgid_file; do
			local file_time=$(stat -c %y "$sgid_file" 2>/dev/null || stat -f %Sm "$sgid_file" 2>/dev/null)
			echo -e "  ${YELLOW}→${NC} $sgid_file ($file_time)"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} SGID文件检查正常"
	fi
}

# 后门持久化检测 (整合现有功能)
backdoor_persistence_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查持久化后门..."
	
	# 检查可疑的定时任务
	local suspicious_cron=$(crontab -l 2>/dev/null | grep -v "^#" | grep -E "(wget|curl|python|bash|sh|nc|socat)")
	if [[ -n "$suspicious_cron" ]]; then
		echo -e "${RED}[WARN]${NC} 发现可疑定时任务:"
		echo "$suspicious_cron" | while read -r cron; do
			echo -e "  ${RED}→${NC} $cron"
			log_message "WARN" "发现可疑定时任务后门: $cron" "backdoorCheck"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 定时任务检查正常"
	fi
	
	# 检查可疑的系统服务
	if command -v systemctl >/dev/null 2>&1; then
		local suspicious_services=$(systemctl list-units --type=service --state=active | grep -E "(backdoor|trojan|malware|hack)")
		if [[ -n "$suspicious_services" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑系统服务:"
			echo "$suspicious_services" | while read -r service; do
				echo -e "  ${RED}→${NC} $service"
				log_message "WARN" "发现可疑服务后门: $service" "backdoorCheck"
			done
		else
			echo -e "${GREEN}[SUCC]${NC} 系统服务检查正常"
		fi
	fi
	
	# 检查启动脚本中的可疑内容
	local startup_paths=("/etc/rc.local" "/etc/init.d" "/etc/systemd/system")
	for path in "${startup_paths[@]}"; do
		if [[ -f "$path" ]] || [[ -d "$path" ]]; then
			local suspicious_startup=$(find "$path" -type f 2>/dev/null | xargs grep -l -E "(nc|socat|bash.*-i|sh.*-i|/dev/tcp)" 2>/dev/null)
			if [[ -n "$suspicious_startup" ]]; then
				echo -e "${RED}[WARN]${NC} 启动脚本中发现可疑内容 ($path):"
				echo "$suspicious_startup" | while read -r file; do
					echo -e "  ${RED}→${NC} $file"
					log_message "WARN" "启动脚本后门: $file" "backdoorCheck"
				done
			fi
		fi
	done
}

# 后门网络检测 (调用现有隧道检测)
backdoor_network_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查网络后门..."
	
	# 检查异常的监听端口
	local suspicious_ports=$(netstat -tlnp 2>/dev/null | grep -v -E ":22|:80|:443|:25|:53|:21|:23" | grep LISTEN)
	if [[ -n "$suspicious_ports" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现非标准监听端口:"
		echo "$suspicious_ports" | while read -r port_info; do
			echo -e "  ${YELLOW}→${NC} $port_info"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 监听端口检查正常"
	fi
	
	# 检查反向连接
	local reverse_connections=$(netstat -anp 2>/dev/null | grep ESTABLISHED | awk '{print $5, $7}' | grep -E ":[1-9][0-9]{3,4}" | head -10)
	if [[ -n "$reverse_connections" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现外部高端口连接 (可能的反向连接):"
		echo "$reverse_connections" | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	fi
}

# 二进制文件时间戳检测 (新增功能)
backdoor_timestamp_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查二进制文件时间戳异常..."
	
	# 检查系统关键目录中最近修改的二进制文件
	local critical_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin")
	local recent_binaries_found=0
	
	for dir in "${critical_dirs[@]}"; do
		if [[ -d "$dir" ]]; then
			# 查找7天内修改的二进制文件
			local recent_binaries=$(find "$dir" -type f -executable -mtime -7 2>/dev/null)
			if [[ -n "$recent_binaries" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} $dir 中7天内修改的二进制文件:"
				echo "$recent_binaries" | while read -r binary; do
					local mtime=$(stat -c %y "$binary" 2>/dev/null || stat -f %Sm "$binary" 2>/dev/null)
					local size=$(du -h "$binary" 2>/dev/null | cut -f1)
					echo -e "  ${YELLOW}→${NC} $binary ($size, $mtime)"
					((recent_binaries_found++))
				done
			fi
		fi
	done
	
	# 检查进程对应的二进制文件修改时间
	echo -e "${BLUE}[INFO]${NC} 检查运行进程的二进制文件时间戳..."
	local suspicious_process_binaries=$(ps aux --no-headers | awk '{print $11}' | sort -u | while read -r proc_path; do
		if [[ -f "$proc_path" ]] && [[ -x "$proc_path" ]]; then
			local mtime_epoch=$(stat -c %Y "$proc_path" 2>/dev/null || stat -f %m "$proc_path" 2>/dev/null)
			local current_epoch=$(date +%s)
			local days_ago=$(( (current_epoch - mtime_epoch) / 86400 ))
			
			if [[ $days_ago -le 7 ]]; then
				echo "$proc_path (${days_ago}天前修改)"
			fi
		fi
	done)
	
	if [[ -n "$suspicious_process_binaries" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 运行中的进程对应的近期修改二进制文件:"
		echo "$suspicious_process_binaries" | while read -r binary_info; do
			echo -e "  ${YELLOW}→${NC} $binary_info"
		done
	fi
	
	if [[ $recent_binaries_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 二进制文件时间戳检查正常"
	else
		echo -e "${YELLOW}[NOTE]${NC} 发现 $recent_binaries_found 个近期修改的二进制文件，建议检查"
	fi
}

# webshell 排查 【已完成】
webshellCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - WEBSHELL" "WebShell检测模块" "START"
	
	# 常见Web目录路径
	local web_paths=(
		"/var/www"
		"/usr/share/nginx"
		"/opt/lampp/htdocs"
		"/home/wwwroot"
		"/data/www"
		"/web"
		"/www"
		"/html"
		"/public_html"
	)
	
	# 自动检测Web目录
	local detected_paths=()
	for path in "${web_paths[@]}"; do
		if [[ -d "$path" ]]; then
			detected_paths+=("$path")
		fi
	done
	
	# 如果没有检测到常见Web目录，搜索包含.php/.jsp文件的目录
	if [[ ${#detected_paths[@]} -eq 0 ]]; then
		log_message "INFO" "未检测到常见Web目录，正在搜索Web文件..." "webshellCheck"
		mapfile -t detected_paths < <(find / -name "*.php" -o -name "*.jsp" 2>/dev/null | head -20 | xargs dirname | sort -u)
	fi
	
	echo -e "${GREEN}[SUCC]${NC} WebShell检测模块开始执行"
	echo -e "${BLUE}[INFO]${NC} 检测目录: ${detected_paths[*]}"
	echo ""
	
	# 如果仍然没有找到Web目录，提示用户
	if [[ ${#detected_paths[@]} -eq 0 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 未检测到Web目录，建议手动指定Web目录进行检查"
		log_message "WARN" "未检测到Web目录" "webshellCheck"
		return 0
	fi
	
	# 执行WebShell检测
	webshell_php_check "${detected_paths[@]}"
	webshell_jsp_check "${detected_paths[@]}"
	webshell_general_check "${detected_paths[@]}"
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - WEBSHELL" "WebShell检测模块" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} WebShell检测模块执行完成"
	printf "\n"  
}

# PHP WebShell检测子函数 【重构增强 - 新增6种检测模式】
webshell_php_check() {
	local web_paths=("$@")
	echo -e "${BLUE}[INFO]${NC} 正在检查PHP WebShell..."
	
	for webpath in "${web_paths[@]}"; do
		if [[ ! -d "$webpath" ]]; then
			continue
		fi
		
		echo -e "${YELLOW}[检查目录]${NC} $webpath"
		
		# 检查常见PHP WebShell特征 (原有5种 + 新增6种 = 11种检测模式)
		local php_patterns=(
			# 【原有】危险函数调用
			"array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|eval\(|system\(|exec\(|shell_exec\(|passthru\("
			# 【原有】WebShell特征字符串
			"phpspy|c99sh|milw0rm|spider_bc|gunerpress|base64_decoolcode"
			# 【原有】编码函数
			"base64_decode\s?\(|gzuncompress\s?\(|gzinflate\(|gzdecode\(|str_rot13\("
			# 【原有】回调函数
			"call_user_func\(|call_user_func_array\(|preg_replace_callback\(|register_shutdown_function\("
			# 【原有】变量函数
			"\(\$\$\w+|\$\w+\(\d+\)\.\$\w+\(\d+\)\."
			# 【新增1】常见函数检测 (phpinfo等)
			"phpinfo|move_uploaded_file|ob_start"
			# 【新增2】数组函数检测 (高风险回调)
			"uasort\(|uksort\(|array_diff_uassoc\(|array_diff_ukey\(|array_intersect_uassoc\(|array_intersect_ukey\(|array_reduce\(|array_filter\(|array_udiff\(|array_walk\(|array_walk_recursive\(|register_tick_function\(|filter_var_array\(|yaml_parse\(|sqlite_create_function\("
			# 【新增3】文件读写函数检测
			"fgetc\(|fgets\(|fgetss\(|fpassthru\(|fread\(|file_get_contents\(|readfile\(|stream_get_contents\(|stream_get_line\(|highlight_file\(|show_source\(|file_put_contents\(|pfsockopen\(|fsockopen\("
			# 【新增4】Java特征检测 (用于混合JSP环境)
			"getruntime|processimpl|processbuilder|defineclass|classloader|naming\.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\\\u0063\\\\u006c\\\\u0061\\\\u0073\\\\u0073"
		)
		
		for pattern in "${php_patterns[@]}"; do
			local result=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P -i "$pattern" 2>/dev/null)
			if [[ -n "$result" ]]; then
				echo -e "${RED}[WARN]${NC} 发现可疑PHP文件:"
				echo "$result" | while read -r file; do
					echo -e "  ${RED}→${NC} $file"
					log_message "WARN" "发现可疑PHP文件: $file" "webshellCheck"
				done
			fi
		done
		
		# 【新增5】变量函数复杂检测 (高级一句话木马)
		local complex_var_result=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P "\\\$\\s*(\\w+)\\s*=[\\s\\(\\{]*(\\$_(GET|POST|REQUEST|COOKIE)\\[.{0,25});[\\s\\S]{0,200}\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\b[\\/*\\s]*\\(+[\\s\"\\/*]*(\\$\\s*\\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(\"]*\\$\\s*\\1))" 2>/dev/null)
		if [[ -n "$complex_var_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现复杂变量函数WebShell:"
			echo "$complex_var_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现复杂变量函数WebShell: $file" "webshellCheck"
			done
		fi
		
		# 【新增6】Filter回调检测 (filter_var FILTER_CALLBACK)
		local filter_callback_result=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P "\\b(filter_var|filter_var_array)\\b\\s*\\(.*FILTER_CALLBACK[^;]*((\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\[.{0,25})|(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))" 2>/dev/null)
		if [[ -n "$filter_callback_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现Filter回调WebShell:"
			echo "$filter_callback_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现Filter回调WebShell: $file" "webshellCheck"
			done
		fi
		
		# 【新增7】PHP://input流检测 (文件流攻击)
		local php_input_result=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P "\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\\b\\s*\\(\\s*(file_get_contents\\s*\\(\\s*)?[\\'\\\"]php:\\/\\/input" 2>/dev/null)
		if [[ -n "$php_input_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现PHP://input流WebShell:"
			echo "$php_input_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现PHP://input流WebShell: $file" "webshellCheck"
			done
		fi
		
		# 检查图片木马 (文件头伪装)
		local image_webshell=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P "^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php" 2>/dev/null)
		if [[ -n "$image_webshell" ]]; then
			echo -e "${RED}[WARN]${NC} 发现图片木马:"
			echo "$image_webshell" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现图片木马: $file" "webshellCheck"
			done
		fi
		
		# 检查一句话木马
		local oneliner=$(find "$webpath" -name "*.php*" -o -name "*.phtml" 2>/dev/null | xargs grep -l -P "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))" 2>/dev/null)
		if [[ -n "$oneliner" ]]; then
			echo -e "${RED}[WARN]${NC} 发现一句话木马:"
			echo "$oneliner" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现一句话木马: $file" "webshellCheck"
			done
		fi
	done
}

# JSP WebShell检测子函数 【重构增强 - 新增Java特征检测】
webshell_jsp_check() {
	local web_paths=("$@")
	echo -e "${BLUE}[INFO]${NC} 正在检查JSP WebShell..."
	
	for webpath in "${web_paths[@]}"; do
		if [[ ! -d "$webpath" ]]; then
			continue
		fi
		
		# 【原有】检查JSP WebShell特征
		local jsp_result=$(find "$webpath" -name "*.jsp*" -o -name "*.jhtml" 2>/dev/null | xargs grep -l -P -i "<%@\spage\simport=[\s\S]*\\\\u00\d+\\\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)" 2>/dev/null)
		if [[ -n "$jsp_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑JSP文件:"
			echo "$jsp_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现可疑JSP文件: $file" "webshellCheck"
			done
		fi
		
		# 【新增】Java特征深度检测 (来自LinuxCheck.sh)
		local java_features_result=$(find "$webpath" -name "*.jsp*" -o -name "*.jhtml" -o -name "*.java" 2>/dev/null | xargs grep -l -P -i "getruntime|processimpl|processbuilder|defineclass|classloader|naming\.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\\\u0063\\\\u006c\\\\u0061\\\\u0073\\\\u0073" 2>/dev/null)
		if [[ -n "$java_features_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现Java特征WebShell:"
			echo "$java_features_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现Java特征WebShell: $file" "webshellCheck"
			done
		fi
		
		# 【新增】JSP一句话木马检测 (request.getParameter + Runtime)
		local jsp_oneliner_result=$(find "$webpath" -name "*.jsp*" -o -name "*.jhtml" 2>/dev/null | xargs grep -l -P -i "Runtime\\.getRuntime\\(\\)\\.exec\\(.*request\\.getParameter\\(|ProcessBuilder.*request\\.getParameter\\(" 2>/dev/null)
		if [[ -n "$jsp_oneliner_result" ]]; then
			echo -e "${RED}[WARN]${NC} 发现JSP一句话木马:"
			echo "$jsp_oneliner_result" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现JSP一句话木马: $file" "webshellCheck"
			done
		fi
	done
}

# 通用WebShell检测子函数
webshell_general_check() {
	local web_paths=("$@")
	echo -e "${BLUE}[INFO]${NC} 正在执行通用WebShell检查..."
	
	for webpath in "${web_paths[@]}"; do
		if [[ ! -d "$webpath" ]]; then
			continue
		fi
		
		# 检查最近修改的Web文件 (24小时内)
		local recent_files=$(find "$webpath" -type f \( -name "*.php*" -o -name "*.jsp*" -o -name "*.asp*" \) -mtime -1 2>/dev/null)
		if [[ -n "$recent_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 24小时内修改的Web文件:"
			echo "$recent_files" | while read -r file; do
				echo -e "  ${YELLOW}→${NC} $file ($(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null))"
			done
		fi
		
		# 检查异常大小的Web文件 (>1MB)
		local large_files=$(find "$webpath" -type f \( -name "*.php*" -o -name "*.jsp*" -o -name "*.asp*" \) -size +1M 2>/dev/null)
		if [[ -n "$large_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 异常大小的Web文件(>1MB):"
			echo "$large_files" | while read -r file; do
				local size=$(du -h "$file" 2>/dev/null | cut -f1)
				echo -e "  ${YELLOW}→${NC} $file ($size)"
			done
		fi
		
		# 检查隐藏的Web文件
		local hidden_files=$(find "$webpath" -type f -name ".*" \( -name "*.php*" -o -name "*.jsp*" -o -name "*.asp*" \) 2>/dev/null)
		if [[ -n "$hidden_files" ]]; then
			echo -e "${RED}[WARN]${NC} 发现隐藏的Web文件:"
			echo "$hidden_files" | while read -r file; do
				echo -e "  ${RED}→${NC} $file"
				log_message "WARN" "发现隐藏Web文件: $file" "webshellCheck"
			done
		fi
	done
}



# SSH隧道检测 【完成 -- 归档 tunnelCheck】
tunnelSSH(){ 
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - TUNNELSSH" "SSH隧道检查模块" "START"
	
	echo -e "${YELLOW}正在检查SSH隧道${NC}"
	log_message "INFO" "正在检查SSH隧道"
	
	# SSH隧道检测
	# 检查网络连接的时候发现2个以上的连接是同一个进程PID,且服务是SSHD的大概率是SSH隧道
	
	## 1. 检测同一PID的多个sshd连接（主要检测方法）
	### [检测的时候发现 unix 连接会干扰判断,所以 netstat 增加-t 参数只显示 tcp 协议的连接(ssh基于tcp)]
	echo -e "${YELLOW}[INFO] 检查同一PID的多个sshd连接:${NC}"
	log_message "INFO" "检查同一PID的多个sshd连接"
	echo -e "${YELLOW}[KNOW] 检测方法: 检查网络连接的时候发现2个以上的连接是同一个进程PID,且服务是SSHD的大概率是SSH隧道${NC}"
	echo -e "${YELLOW}[KNOW] 检查结果需要排除父进程 1 的SSHD系统服务进程,例如: PSINFO:  xxx     1 root     /usr/sbin/sshd -D ${NC}"
	log_message "INFO" "检测方法: 检查网络连接的时候发现2个以上的连接是同一个进程PID,且服务是SSHD的大概率是SSH隧道"
	ssh_connections=$(netstat -anpot 2>/dev/null | grep sshd | awk '{print $7}' | cut -d'/' -f1 | sort | uniq -c | awk '$1 > 1 {print $2, $1}')
	if [ $? -ne 0 ]; then
		handle_error 1 "执行netstat命令检查SSH连接失败" "tunnelSSH"
	fi
	if [ -n "$ssh_connections" ]; then
		echo -e "${RED}[WARN] 发现可疑SSH隧道 - 同一PID存在多个SSHD连接:${NC}"
		log_message "INFO" "发现可疑SSH隧道 - 同一PID存在多个SSHD连接"
		echo "$ssh_connections" | while read pid count; do
			if [ -n "$pid" ] && [ "$pid" != "-" ]; then
				echo -e "${RED}  PID: $pid, 连接数: $count${NC}"
				log_message "INFO" "PID: $pid, 连接数: $count"
				# 显示详细连接信息
				netstat -anpot 2>/dev/null | grep "$pid/sshd" | while read line; do
					echo -e "${YELLOW}    $line${NC}"
				done
				# 显示进程详细信息
				ps_info=$(ps -p $pid -o pid,ppid,user,cmd --no-headers 2>/dev/null)
				if [ -n "$ps_info" ]; then
					echo -e "${YELLOW}    COLUMN: pid - ppid - user - cmd ${NC}"
					echo -e "${YELLOW}    PSINFO: $ps_info${NC}"
					# log_message "INFO" "进程详细信息: $ps_info"
				fi
				echo ""
			fi
		done
	else
		echo -e "${GREEN}[SUCC] 未发现同一PID的多个sshd连接${NC}"
		log_message "INFO" "未发现同一PID的多个sshd连接"
	fi
	printf "\n"
	
	## 2. 检测SSH本地转发（Local Port Forwarding）
	echo -e "${YELLOW}[INFO] 检查SSH本地转发特征:${NC}"
	log_message "INFO" "检查SSH本地转发特征"
	# 本地转发命令：ssh -L local_port:target_host:target_port user@ssh_server
	# 特征：SSH进程监听本地端口,将流量转发到远程
	local_forward_ports=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4, $7}' | grep -v ':22')
	if [ $? -ne 0 ]; then
		handle_error 1 "执行netstat命令检查SSH本地转发失败" "tunnelSSH"
	fi
	if [ -n "$local_forward_ports" ]; then
		echo -e "${RED}[WARN] 发现SSH进程监听非22端口(可能的本地转发):${NC}"
		log_message "INFO" "发现SSH进程监听非22端口(可能的本地转发)"
		echo "$local_forward_ports"
		# 检查对应的SSH进程命令行参数
		echo "$local_forward_ports" | while read port_info; do
			pid=$(echo "$port_info" | awk '{print $2}' | cut -d'/' -f1)
			if [ -n "$pid" ] && [ "$pid" != "-" ]; then
				cmd_line=$(ps -p $pid -o cmd --no-headers 2>/dev/null)
				if echo "$cmd_line" | grep -q '\-L'; then
					echo -e "${RED}    [WARN] 确认本地转发: $cmd_line${NC}"
					log_message "INFO" "确认本地转发: $cmd_line"
				fi
			fi
		done
	else
		echo -e "${GREEN}[SUCC] 未发现SSH本地转发特征${NC}"
		log_message "INFO" "未发现SSH本地转发特征"
	fi
	printf "\n"
	
	## 3. 检测SSH远程转发（Remote Port Forwarding）
	echo -e "${YELLOW}[INFO] 检查SSH远程转发特征:${NC}"
	log_message "INFO" "检查SSH远程转发特征"
	# 远程转发命令：ssh -R remote_port:local_host:local_port user@ssh_server
	# 特征：SSH客户端连接到远程服务器,远程服务器监听端口
	
	### 3.1 检查SSH进程的命令行参数中是否包含-R选项
	remote_forward_processes=$(ps aux 2>/dev/null | grep ssh | grep -v grep | grep '\-R')
	if [ $? -ne 0 ]; then
		handle_error 1 "执行ps命令检查SSH远程转发进程失败" "tunnelSSH"
	fi
	if [ -n "$remote_forward_processes" ]; then
		echo -e "${RED}[WARN] 发现SSH远程转发进程:${NC}"
		log_message "INFO" "发现SSH远程转发进程"
		echo "$remote_forward_processes"
	else
		echo -e "${GREEN}[SUCC] 未发现SSH远程转发特征${NC}"
		log_message "INFO" "未发现SSH远程转发特征"
	fi
	
	### 3.2 检查SSH配置文件中的远程转发设置
	remote_forward_config=$(grep -E '^(AllowTcpForwarding|GatewayPorts)' /etc/ssh/sshd_config 2>/dev/null | grep -v 'no')
	if [ -n "$remote_forward_config" ]; then
		echo -e "${RED}[WARN] SSH配置允许远程转发:${NC}"
		log_message "INFO" "SSH配置允许远程转发"
		echo "$remote_forward_config"
	fi
	printf "\n"
	
	## 4. 检测SSH动态转发（SOCKS代理）
	echo -e "${YELLOW}[INFO] 检查SSH动态转发(SOCKS代理)特征:${NC}"
	log_message "INFO" "检查SSH动态转发(SOCKS代理)特征"
	# 动态转发命令：ssh -D local_port user@ssh_server
	# - 排除 sshd -D （SSH守护进程的调试模式）
	# - 排除 /usr/sbin/sshd （系统SSH服务）
	# - 只检测真正的SSH客户端动态转发
	# 特征：SSH进程创建SOCKS代理,监听本地端口
	echo -e "${YELLOW}[KNOW] :检查结果需要排除SSHD系统服务进程${NC}"
	log_message "INFO" "检查结果需要排除SSHD系统服务进程"
	# dynamic_forward_processes=$(ps aux | grep ssh | grep -v grep | grep '\-D')
	dynamic_forward_processes=$(ps aux 2>/dev/null | grep -E 'ssh.*-D' | grep -v grep | grep -v 'sshd.*-D' | grep -v '/usr/sbin/sshd')
	if [ $? -ne 0 ]; then
		handle_error 1 "执行ps命令检查SSH动态转发进程失败" "tunnelSSH"
	fi
	if [ -n "$dynamic_forward_processes" ]; then
		echo -e "${RED}[WARN] 发现SSH动态转发(SOCKS代理)进程:${NC}"
		log_message "INFO" "发现SSH动态转发(SOCKS代理)进程"
		echo "$dynamic_forward_processes"
	else
		echo -e "${GREEN}[SUCC] 未发现SSH动态转发特征${NC}"
		log_message "INFO" "未发现SSH动态转发特征"
	fi
	printf "\n"
	
	## 5. 检测SSH多级跳板（ProxyJump/ProxyCommand）
	echo -e "${YELLOW}[INFO] 检查SSH多级跳板特征:${NC}"
	log_message "INFO" "检查SSH多级跳板特征"
	# 多级跳板命令：ssh -J jump_host1,jump_host2 target_host
	# 或使用ProxyCommand: ssh -o ProxyCommand="ssh jump_host nc target_host 22" target_host
	### 5.1 检查SSH进程的命令行参数
	jump_processes=$(ps aux 2>/dev/null | grep ssh | grep -v grep | grep -E '(\-J|ProxyCommand|ProxyJump)')
	if [ $? -ne 0 ]; then
		handle_error 1 "执行ps命令检查SSH多级跳板进程失败" "tunnelSSH"
	fi
	if [ -n "$jump_processes" ]; then
		echo -e "${RED}[WARN] 发现SSH多级跳板进程:${NC}"
		log_message "INFO" "发现SSH多级跳板进程"
		echo "$jump_processes"
	else
		echo -e "${GREEN}[SUCC] 未发现SSH多级跳板进程${NC}"
		log_message "INFO" "未发现SSH多级跳板进程"
	fi
	
	### 5.2 检查SSH配置文件中的跳板设置
	if [ -f ~/.ssh/config ]; then
		jump_config=$(grep -E '(ProxyJump|ProxyCommand)' ~/.ssh/config 2>/dev/null)
		if [ -n "$jump_config" ]; then
			echo -e "${RED}[WARN] SSH配置文件中发现跳板设置:${NC}"
			log_message "INFO" "SSH配置文件中发现跳板设置"
			echo "$jump_config"
		fi
	fi
	printf "\n"
	
	## 6. 检测SSH隧道的网络流量特征
	echo -e "${YELLOW}[INFO] 检查SSH隧道网络流量特征:${NC}"
	log_message "INFO" "检查SSH隧道网络流量特征"
	
	# 6.1 检查总体网络流量（分级阈值检测）
	ssh_traffic=$(cat /proc/net/dev 2>/dev/null | awk '
		NR>2 && !/lo:/ {
			# $2=接收字节数, $10=发送字节数
			rx_bytes+=$2; tx_bytes+=$10
		} 
		END {
			rx_mb=rx_bytes/1024/1024; tx_mb=tx_bytes/1024/1024;
			total_mb=rx_mb+tx_mb;
			
			# 分级阈值检测 (MB)
			if(total_mb>20480) {        # >20GB 极高危
				printf "CRITICAL|%.2f|%.2f|%.2f|EXTREME_RISK", rx_mb, tx_mb, total_mb
			} else if(total_mb>5120) {  # >5GB 高危  
				printf "HIGH|%.2f|%.2f|%.2f|HIGH_RISK", rx_mb, tx_mb, total_mb
			} else if(total_mb>1024) {  # >1GB 中危
				printf "MEDIUM|%.2f|%.2f|%.2f|MEDIUM_RISK", rx_mb, tx_mb, total_mb
			} else if(total_mb>200) {   # >200MB 关注
				printf "LOW|%.2f|%.2f|%.2f|ATTENTION", rx_mb, tx_mb, total_mb
			} else {                    # <=200MB 正常
				printf "NORMAL|%.2f|%.2f|%.2f|NORMAL", rx_mb, tx_mb, total_mb
			}
		}')
	
	# 解析检测结果
	if [ -n "$ssh_traffic" ]; then
		level=$(echo "$ssh_traffic" | cut -d'|' -f1)
		rx_mb=$(echo "$ssh_traffic" | cut -d'|' -f2)
		tx_mb=$(echo "$ssh_traffic" | cut -d'|' -f3)
		total_mb=$(echo "$ssh_traffic" | cut -d'|' -f4)
		risk_level=$(echo "$ssh_traffic" | cut -d'|' -f5)
		
		case "$level" in
			"CRITICAL")
				echo -e "${RED}[WARN] 检测到极高网络流量(>20GB) - 疑似严重安全威胁:${NC}"
				echo -e "${RED}    接收: ${rx_mb}MB | 发送: ${tx_mb}MB | 总计: ${total_mb}MB${NC}"
				echo -e "${RED}[建议]立即断开可疑SSH连接,检查数据泄露风险${NC}"
				;;
			"HIGH")
				echo -e "${RED}[WARN] 检测到高网络流量(5-20GB) - 需要紧急关注:${NC}"
				echo -e "${RED}    接收: ${rx_mb}MB | 发送: ${tx_mb}MB | 总计: ${total_mb}MB${NC}"
				echo -e "${YELLOW}[建议]检查SSH隧道进程和大文件传输活动${NC}"
				;;
			"MEDIUM")
				echo -e "${RED}[WARN] 检测到中等网络流量(1-5GB) - 建议关注:${NC}"
				echo -e "${YELLOW}    接收: ${rx_mb}MB | 发送: ${tx_mb}MB | 总计: ${total_mb}MB${NC}"
				echo -e "${YELLOW}[建议]确认是否为正常业务操作${NC}"
				;;
			"LOW")
				echo -e "${YELLOW}[INFO] 检测到轻度网络流量(200MB-1GB) - 正常范围:${NC}"
				echo -e "${GREEN}    接收: ${rx_mb}MB | 发送: ${tx_mb}MB | 总计: ${total_mb}MB${NC}"
				;;
			"NORMAL")
				echo -e "${YELLOW}[INFO] 网络流量正常(<200MB):${NC}"
				echo -e "${GREEN}    接收: ${rx_mb}MB | 发送: ${tx_mb}MB | 总计: ${total_mb}MB${NC}"
				;;
		esac
	else
		echo -e "${YELLOW}[INFO] 无法获取网络流量信息${NC}"
	fi
	printf "\n"
	
	## 7. 检测SSH隧道持久化特征
	echo -e "${YELLOW}[INFO] 检查SSH隧道持久化特征:${NC}"
	log_message "INFO" "检查SSH隧道持久化特征"
	
	### 7.1 检查SSH相关的定时任务
	ssh_cron=$(crontab -l 2>/dev/null | grep ssh)
	if [ -n "$ssh_cron" ]; then
		echo -e "${RED}[WARN] 发现SSH相关的定时任务:${NC}"
		log_message "INFO" "发现SSH相关的定时任务"
		echo "$ssh_cron"
	fi
	
	### 7.2 检查SSH相关的systemd服务
	ssh_services=$(systemctl list-units --type=service 2>/dev/null | grep ssh | grep -v sshd)
	if [ -n "$ssh_services" ]; then
		echo -e "${RED}[WARN] 发现SSH相关的自定义服务:${NC}"
		log_message "INFO" "发现SSH相关的自定义服务"
		echo "$ssh_services"
	fi
	
	### 7.3 检查SSH相关的启动脚本
	ssh_startup=$(find /etc/init.d /etc/systemd/system /etc/rc.local 2>/dev/null -exec grep -l "ssh.*-[LRD]" {} \; 2>/dev/null)
	if [ -n "$ssh_startup" ]; then
		echo -e "${RED}[WARN] 发现SSH隧道相关的启动脚本:${NC}"
		log_message "INFO" "发现SSH隧道相关的启动脚本"
		echo "$ssh_startup"
	fi
	printf "\n"
	
	## 8. 检测其他隧道工具
	echo -e "${YELLOW}[INFO] 检查其他隧道工具:${NC}"
	# 隧道工具列表定义 - 常见隧道工具
	tunnel_tools="frp nps spp ngrok es suo5 chisel socat nc netcat ncat stunnel proxychains v2ray xray clash lcx portmap autossh"
	for tool in $tunnel_tools; do
		# 使用单词边界匹配,避免部分匹配导致的误报  (\s|/) 确保工具名前面是空格或路径分隔符  (\s|$) 确保工具名后面是空格或行尾
		tool_process=$(ps aux | grep -v grep | grep -E "(\s|/)$tool(\s|$)")
		if [ -n "$tool_process" ]; then
			echo -e "${RED}[WARN] 发现隧道工具: $tool${NC}"
			echo -e "${RED}[WARN] 发现隧道工具进程:${NC}"
			echo -e "$tool_process"
		fi
		# 检查工具是否存在于系统中
		tool_path=$(which "$tool" 2>/dev/null)
		if [ -n "$tool_path" ]; then
			echo -e "${RED}[WARN] 系统中存在隧道工具: $tool ($tool_path)${NC}"
		fi
	done
	printf "\n"
	
	echo -e "${GREEN}SSH隧道检测完成${NC}"
	
	# 记录结束时间和性能统计
	end_time=$(date +%s)
	log_performance "tunnelSSH" "$start_time" "$end_time"
	log_operation "MOUDLE - TUNNELSSH" "SSH隧道检查模块执行完成" "END"

}

# HTTP隧道检测 【新增完成】
tunnelHTTP(){ 
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - TUNNELHTTP" "HTTP隧道检测模块" "START"
	
	echo -e "${YELLOW}正在检查HTTP隧道${NC}"
	log_message "INFO" "正在检查HTTP隧道"
	
	# 1. 检查HTTP CONNECT方法（最常见的HTTP隧道特征）
	echo -e "${YELLOW}[INFO] 检查HTTP CONNECT方法连接:${NC}"
	log_message "INFO" "检查HTTP CONNECT方法连接"
	
	# 检查Web服务器日志中的CONNECT方法
	local web_logs=("/var/log/nginx/access.log" "/var/log/apache2/access.log" "/var/log/httpd/access_log" "/var/log/apache/access.log")
	local connect_found=0
	
	for log_file in "${web_logs[@]}"; do
		if [[ -f "$log_file" ]]; then
			local connect_requests=$(grep -i "CONNECT" "$log_file" 2>/dev/null | tail -10)
			if [[ -n "$connect_requests" ]]; then
				echo -e "${RED}[WARN]${NC} 在 $log_file 中发现CONNECT方法请求:"
				echo "$connect_requests" | while read -r request; do
					echo -e "  ${RED}→${NC} $request"
					log_message "WARN" "HTTP CONNECT请求: $request" "tunnelHTTP"
					((connect_found++))
				done
			fi
		fi
	done
	
	if [[ $connect_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未在Web日志中发现CONNECT方法请求"
	fi
	
	# 2. 检查异常的HTTP代理进程
	echo -e "${YELLOW}[INFO] 检查HTTP代理进程:${NC}"
	log_message "INFO" "检查HTTP代理进程"
	
	local proxy_processes=$(ps aux | grep -v grep | grep -i -E "(squid|proxy|3128|8080|8888|privoxy|tinyproxy)")
	if [[ -n "$proxy_processes" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现HTTP代理相关进程:"
		echo "$proxy_processes" | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现HTTP代理进程"
	fi
	
	# 3. 检查HTTP隧道工具特征
	echo -e "${YELLOW}[INFO] 检查HTTP隧道工具:${NC}"
	log_message "INFO" "检查HTTP隧道工具"
	
	local tunnel_tools=(
		"httptunnel" "corkscrew" "proxytunnel" "connect-proxy"
		"chisel" "frp" "ngrok" "localtunnel" "serveo"
	)
	
	local tools_found=0
	for tool in "${tunnel_tools[@]}"; do
		local tool_processes=$(ps aux | grep -v grep | grep -i "$tool")
		if [[ -n "$tool_processes" ]]; then
			echo -e "${RED}[WARN]${NC} 发现HTTP隧道工具 ($tool):"
			echo "$tool_processes" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "HTTP隧道工具: $proc" "tunnelHTTP"
				((tools_found++))
			done
		fi
		
		# 检查工具文件是否存在
		local tool_files=$(find / -name "*$tool*" -type f -executable 2>/dev/null | head -5)
		if [[ -n "$tool_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现HTTP隧道工具文件 ($tool):"
			echo "$tool_files" | while read -r file; do
				echo -e "  ${YELLOW}→${NC} $file"
			done
		fi
	done
	
	if [[ $tools_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的HTTP隧道工具"
	fi
	
	# 4. 检查异常的HTTP流量模式
	echo -e "${YELLOW}[INFO] 检查异常HTTP流量模式:${NC}"
	log_message "INFO" "检查异常HTTP流量模式"
	
	# 检查长时间保持的HTTP连接
	local long_connections=$(netstat -anp 2>/dev/null | grep ":80\|:8080\|:3128\|:8888" | grep ESTABLISHED | wc -l)
	if [[ $long_connections -gt 10 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现较多的HTTP连接 ($long_connections 个)，可能存在隧道流量"
		netstat -anp 2>/dev/null | grep ":80\|:8080\|:3128\|:8888" | grep ESTABLISHED | head -10 | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} HTTP连接数量正常 ($long_connections 个)"
	fi
	
	# 5. 检查可疑的User-Agent
	echo -e "${YELLOW}[INFO] 检查可疑的User-Agent:${NC}"
	for log_file in "${web_logs[@]}"; do
		if [[ -f "$log_file" ]]; then
			local suspicious_ua=$(grep -i -E "(tunnel|proxy|connect)" "$log_file" 2>/dev/null | tail -5)
			if [[ -n "$suspicious_ua" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 在 $log_file 中发现可疑User-Agent:"
				echo "$suspicious_ua" | while read -r ua; do
					echo -e "  ${YELLOW}→${NC} $ua"
				done
			fi
		fi
	done
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - TUNNELHTTP" "HTTP隧道检测模块" "END" "$execution_time"
	
	printf "\n"
}

# DNS隧道检测 【新增完成】
tunnelDNS(){ 
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - TUNNELDNS" "DNS隧道检测模块" "START"
	
	echo -e "${YELLOW}正在检查DNS隧道${NC}"
	log_message "INFO" "正在检查DNS隧道"
	
	# 1. 检查DNS隧道工具进程
	echo -e "${YELLOW}[INFO] 检查DNS隧道工具进程:${NC}"
	log_message "INFO" "检查DNS隧道工具进程"
	
	local dns_tunnel_tools=(
		"dnscat" "iodine" "dns2tcp" "ozymandns" "tuns"
		"dnscapy" "dnsteal" "dnspot" "powerdns" "cobalt"
	)
	
	local dns_tools_found=0
	for tool in "${dns_tunnel_tools[@]}"; do
		local tool_processes=$(ps aux | grep -v grep | grep -i "$tool")
		if [[ -n "$tool_processes" ]]; then
			echo -e "${RED}[WARN]${NC} 发现DNS隧道工具 ($tool):"
			echo "$tool_processes" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "DNS隧道工具: $proc" "tunnelDNS"
				((dns_tools_found++))
			done
		fi
		
		# 检查工具文件是否存在
		local tool_files=$(find / -name "*$tool*" -type f -executable 2>/dev/null | head -3)
		if [[ -n "$tool_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现DNS隧道工具文件 ($tool):"
			echo "$tool_files" | while read -r file; do
				echo -e "  ${YELLOW}→${NC} $file"
			done
		fi
	done
	
	if [[ $dns_tools_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的DNS隧道工具"
	fi
	
	# 2. 检查异常的DNS查询频率
	echo -e "${YELLOW}[INFO] 检查DNS查询频率异常:${NC}"
	log_message "INFO" "检查DNS查询频率异常"
	
	# 检查DNS查询日志（如果存在）
	local dns_logs=("/var/log/named/queries.log" "/var/log/bind/queries.log" "/var/log/dns.log")
	local high_frequency_found=0
	
	for log_file in "${dns_logs[@]}"; do
		if [[ -f "$log_file" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 分析DNS日志: $log_file"
			# 统计最近1小时的查询频率
			local recent_queries=$(grep "$(date '+%d-%b-%Y %H')" "$log_file" 2>/dev/null | wc -l)
			if [[ $recent_queries -gt 1000 ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 最近1小时DNS查询数量较高: $recent_queries 次"
				((high_frequency_found++))
			fi
		fi
	done
	
	# 3. 检查可疑的DNS域名模式
	echo -e "${YELLOW}[INFO] 检查可疑的DNS域名模式:${NC}"
	log_message "INFO" "检查可疑的DNS域名模式"
	
	# 检查/etc/hosts文件中的可疑域名
	if [[ -f "/etc/hosts" ]]; then
		local suspicious_domains=$(grep -v "^#" /etc/hosts 2>/dev/null | grep -E "\.(tk|ml|ga|cf|gq)$|\b[a-f0-9]{8,}\b")
		if [[ -n "$suspicious_domains" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} /etc/hosts中发现可疑域名:"
			echo "$suspicious_domains" | while read -r domain; do
				echo -e "  ${YELLOW}→${NC} $domain"
			done
		fi
	fi
	
	# 4. 检查DNS解析器配置
	echo -e "${YELLOW}[INFO] 检查DNS解析器配置:${NC}"
	log_message "INFO" "检查DNS解析器配置"
	
	if [[ -f "/etc/resolv.conf" ]]; then
		local dns_servers=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')
		echo -e "${YELLOW}[NOTE]${NC} 当前DNS服务器配置:"
		echo "$dns_servers" | while read -r server; do
			echo -e "  ${YELLOW}→${NC} $server"
			# 检查是否为常见的公共DNS
			if [[ "$server" =~ ^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|208\.67\.222\.222|208\.67\.220\.220)$ ]]; then
				echo -e "    ${GREEN}[INFO]${NC} 公共DNS服务器"
			else
				echo -e "    ${YELLOW}[NOTE]${NC} 自定义DNS服务器，建议检查"
			fi
		done
	fi
	
	# 5. 检查异常的DNS流量
	echo -e "${YELLOW}[INFO] 检查DNS网络连接:${NC}"
	log_message "INFO" "检查DNS网络连接"
	
	# 检查非标准端口的DNS连接
	local dns_connections=$(netstat -anp 2>/dev/null | grep -v ":53 " | grep -E "dns|domain" | grep ESTABLISHED)
	if [[ -n "$dns_connections" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现非标准端口的DNS相关连接:"
		echo "$dns_connections" | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} DNS连接检查正常"
	fi
	
	# 检查大量UDP 53端口连接
	local udp_dns_count=$(netstat -anp 2>/dev/null | grep ":53 " | grep udp | wc -l)
	if [[ $udp_dns_count -gt 50 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现大量DNS UDP连接 ($udp_dns_count 个)，可能存在DNS隧道"
		netstat -anp 2>/dev/null | grep ":53 " | grep udp | head -10 | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} DNS UDP连接数量正常 ($udp_dns_count 个)"
	fi
	
	# 6. 检查DNS缓存中的可疑记录
	echo -e "${YELLOW}[INFO] 检查DNS缓存:${NC}"
	if command -v systemd-resolve >/dev/null 2>&1; then
		local dns_cache=$(systemd-resolve --statistics 2>/dev/null)
		if [[ -n "$dns_cache" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} DNS缓存统计:"
			echo "$dns_cache" | grep -E "(Cache|Current|DNSSEC)" | while read -r stat; do
				echo -e "  ${YELLOW}→${NC} $stat"
			done
		fi
	else
		echo -e "${YELLOW}[NOTE]${NC} systemd-resolve不可用，跳过DNS缓存检查"
	fi
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - TUNNELDNS" "DNS隧道检测模块" "END" "$execution_time"
	
	printf "\n"
}

# ICMP隧道检测 【新增完成】
tunnelICMP(){ 
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - TUNNELICMP" "ICMP隧道检测模块" "START"
	
	echo -e "${YELLOW}正在检查ICMP隧道${NC}"
	log_message "INFO" "正在检查ICMP隧道"
	
	# 1. 检查ICMP隧道工具进程
	echo -e "${YELLOW}[INFO] 检查ICMP隧道工具进程:${NC}"
	log_message "INFO" "检查ICMP隧道工具进程"
	
	local icmp_tunnel_tools=(
		"icmptunnel" "pingtunnel" "ptunnel" "icmpsh"
		"icmp_backdoor" "icmpknock" "loki" "icmptx"
		"hans" "icmpexfil" "icmpv6tunnel"
	)
	
	local icmp_tools_found=0
	for tool in "${icmp_tunnel_tools[@]}"; do
		local tool_processes=$(ps aux | grep -v grep | grep -i "$tool")
		if [[ -n "$tool_processes" ]]; then
			echo -e "${RED}[WARN]${NC} 发现ICMP隧道工具 ($tool):"
			echo "$tool_processes" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "ICMP隧道工具: $proc" "tunnelICMP"
				((icmp_tools_found++))
			done
		fi
		
		# 检查工具文件是否存在
		local tool_files=$(find / -name "*$tool*" -type f -executable 2>/dev/null | head -3)
		if [[ -n "$tool_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现ICMP隧道工具文件 ($tool):"
			echo "$tool_files" | while read -r file; do
				echo -e "  ${YELLOW}→${NC} $file"
			done
		fi
	done
	
	if [[ $icmp_tools_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的ICMP隧道工具"
	fi
	
	# 2. 检查异常的ICMP流量模式
	echo -e "${YELLOW}[INFO] 检查ICMP流量异常:${NC}"
	log_message "INFO" "检查ICMP流量异常"
	
	# 检查ICMP相关的网络连接（虽然ICMP不是基于连接的）
	if command -v ss >/dev/null 2>&1; then
		local icmp_sockets=$(ss -u -a 2>/dev/null | grep -i icmp)
		if [[ -n "$icmp_sockets" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现ICMP相关套接字:"
			echo "$icmp_sockets" | while read -r socket; do
				echo -e "  ${YELLOW}→${NC} $socket"
			done
		fi
	fi
	
	# 3. 检查原始套接字使用情况
	echo -e "${YELLOW}[INFO] 检查原始套接字使用:${NC}"
	log_message "INFO" "检查原始套接字使用"
	
	# 检查使用原始套接字的进程（ICMP隧道通常需要原始套接字）
	local raw_socket_processes=$(lsof -i -P 2>/dev/null | grep -i "raw\|icmp" | head -10)
	if [[ -n "$raw_socket_processes" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现使用原始套接字的进程:"
		echo "$raw_socket_processes" | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现异常的原始套接字使用"
	fi
	
	# 4. 检查ping命令的异常使用
	echo -e "${YELLOW}[INFO] 检查ping命令异常使用:${NC}"
	log_message "INFO" "检查ping命令异常使用"
	
	# 检查是否有长时间运行的ping进程
	local long_ping_processes=$(ps aux | grep -v grep | grep ping | awk '$10 > 60 {print $0}' 2>/dev/null)
	if [[ -n "$long_ping_processes" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现长时间运行的ping进程:"
		echo "$long_ping_processes" | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} ping进程使用正常"
	fi
	
	# 检查ping命令的异常参数
	local suspicious_ping=$(ps aux | grep -v grep | grep ping | grep -E "(-s [0-9]{3,}|-i 0\.[0-9]|-c [0-9]{4,})")
	if [[ -n "$suspicious_ping" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现使用异常参数的ping命令:"
		echo "$suspicious_ping" | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	fi
	
	# 5. 检查ICMP相关的网络统计
	echo -e "${YELLOW}[INFO] 检查ICMP网络统计:${NC}"
	log_message "INFO" "检查ICMP网络统计"
	
	if [[ -f "/proc/net/snmp" ]]; then
		local icmp_stats=$(grep "^Icmp:" /proc/net/snmp | tail -1)
		if [[ -n "$icmp_stats" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} ICMP统计信息:"
			echo -e "  ${YELLOW}→${NC} $icmp_stats"
			
			# 提取关键统计数据
			local icmp_values=($icmp_stats)
			if [[ ${#icmp_values[@]} -gt 10 ]]; then
				local in_msgs=${icmp_values[1]}
				local out_msgs=${icmp_values[9]}
				echo -e "  ${YELLOW}→${NC} 入站ICMP消息: $in_msgs"
				echo -e "  ${YELLOW}→${NC} 出站ICMP消息: $out_msgs"
				
				# 检查是否有异常高的ICMP流量
				if [[ $in_msgs -gt 10000 ]] || [[ $out_msgs -gt 10000 ]]; then
					echo -e "  ${YELLOW}[NOTE]${NC} ICMP流量较高，可能存在隧道活动"
				fi
			fi
		fi
	fi
	
	# 6. 检查防火墙中的ICMP规则
	echo -e "${YELLOW}[INFO] 检查防火墙ICMP规则:${NC}"
	log_message "INFO" "检查防火墙ICMP规则"
	
	# 检查iptables中的ICMP规则
	if command -v iptables >/dev/null 2>&1; then
		local icmp_rules=$(iptables -L -n 2>/dev/null | grep -i icmp)
		if [[ -n "$icmp_rules" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现ICMP相关防火墙规则:"
			echo "$icmp_rules" | while read -r rule; do
				echo -e "  ${YELLOW}→${NC} $rule"
			done
		else
			echo -e "${GREEN}[SUCC]${NC} 未发现特殊的ICMP防火墙规则"
		fi
	fi
	
	# 7. 检查系统日志中的ICMP异常
	echo -e "${YELLOW}[INFO] 检查系统日志中的ICMP记录:${NC}"
	local log_files=("/var/log/messages" "/var/log/syslog" "/var/log/kern.log")
	
	for log_file in "${log_files[@]}"; do
		if [[ -f "$log_file" ]]; then
			local icmp_logs=$(grep -i "icmp" "$log_file" 2>/dev/null | tail -5)
			if [[ -n "$icmp_logs" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} $log_file 中的ICMP记录:"
				echo "$icmp_logs" | while read -r log_entry; do
					echo -e "  ${YELLOW}→${NC} $log_entry"
				done
			fi
		fi
	done
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - TUNNELICMP" "ICMP隧道检测模块" "END" "$execution_time"
	
	printf "\n"
}

# 隧道和反弹shell检查 【隧道检测主函数 -- 在主函数 main 中调用】
tunnelCheck(){ 
	echo -e "${YELLOW}正在检查隧道和反弹shell${NC}"
	echo -e "${YELLOW}正在检查SSH隧道(调用检测函数)${NC}"
	tunnelSSH
	echo -e "${YELLOW}正在检查HTTP隧道${NC}"
	tunnelHTTP
	echo -e "${YELLOW}正在检查DNS隧道${NC}"
	tunnelDNS
	echo -e "${YELLOW}正在检查ICMP隧道${NC}"
	tunnelICMP
	echo -e "${YELLOW}正在检测反弹shell${NC}"
	reverseShellCheck
}

# 反弹shell检测 【新增完成】
reverseShellCheck() {
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - REVERSESHELL" "反弹shell检测模块" "START"
	
	echo -e "${BLUE}[INFO]${NC} 正在检查反弹shell特征..."
	log_message "INFO" "正在检查反弹shell特征"
	
	# 1. 检查反弹shell相关进程
	echo -e "${YELLOW}[INFO] 检查反弹shell进程特征:${NC}"
	log_message "INFO" "检查反弹shell进程特征"
	
	local reverse_shell_patterns=(
		# 常见反弹shell命令特征
		"bash.*-i.*>&.*" "sh.*-i.*>&.*" "/bin/bash.*-i" "/bin/sh.*-i"
		"nc.*-e.*bash" "nc.*-e.*sh" "ncat.*-e" "netcat.*-e"
		"socat.*exec" "socat.*system" "python.*socket.*connect"
		"perl.*socket.*connect" "php.*fsockopen" "ruby.*socket"
		# /dev/tcp 和 /dev/udp 重定向
		"/dev/tcp/.*/" "/dev/udp/.*/" "exec.*>/dev/tcp" "exec.*>/dev/udp"
		# 编码的反弹shell
		"base64.*bash" "base64.*sh" "echo.*base64.*bash"
	)
	
	local reverse_found=0
	for pattern in "${reverse_shell_patterns[@]}"; do
		local suspicious_procs=$(ps aux | grep -v grep | grep -E "$pattern")
		if [[ -n "$suspicious_procs" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑反弹shell进程 ($pattern):"
			echo "$suspicious_procs" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "发现反弹shell进程: $proc" "reverseShellCheck"
				((reverse_found++))
			done
		fi
	done
	
	if [[ $reverse_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现反弹shell进程特征"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $reverse_found 个可疑反弹shell进程"
	fi
	
	# 2. 检查历史命令中的反弹shell
	echo -e "${YELLOW}[INFO] 检查历史命令中的反弹shell:${NC}"
	log_message "INFO" "检查历史命令中的反弹shell"
	
	local history_files=("/root/.bash_history" "/home/*/.bash_history" "/root/.zsh_history" "/home/*/.zsh_history")
	local history_found=0
	
	for history_pattern in "${history_files[@]}"; do
		for history_file in $history_pattern; do
			if [[ -f "$history_file" ]]; then
				local reverse_commands=$(grep -E "(bash.*-i.*>&|nc.*-e|/dev/tcp|socat.*exec|python.*socket.*connect)" "$history_file" 2>/dev/null | tail -5)
				if [[ -n "$reverse_commands" ]]; then
					echo -e "${RED}[WARN]${NC} 在 $history_file 中发现反弹shell命令:"
					echo "$reverse_commands" | while read -r cmd; do
						echo -e "  ${RED}→${NC} $cmd"
						log_message "WARN" "历史命令反弹shell: $cmd" "reverseShellCheck"
						((history_found++))
					done
				fi
			fi
		done
	done
	
	if [[ $history_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 历史命令中未发现反弹shell"
	fi
	
	# 3. 检查网络连接中的反向连接
	echo -e "${YELLOW}[INFO] 检查可疑的外部连接:${NC}"
	log_message "INFO" "检查可疑的外部连接"
	
	# 检查连接到高端口的外部连接
	local suspicious_connections=$(netstat -anp 2>/dev/null | grep ESTABLISHED | awk '{print $5, $7}' | grep -E ":[1-9][0-9]{3,4}[[:space:]]" | head -10)
	if [[ -n "$suspicious_connections" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现连接到高端口的外部连接 (可能的反向连接):"
		echo "$suspicious_connections" | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现可疑的外部高端口连接"
	fi
	
	# 4. 检查反弹shell工具文件
	echo -e "${YELLOW}[INFO] 检查反弹shell工具文件:${NC}"
	log_message "INFO" "检查反弹shell工具文件"
	
	local reverse_tools=("nc" "ncat" "netcat" "socat" "telnet")
	local tools_in_tmp=0
	
	for tool in "${reverse_tools[@]}"; do
		# 检查临时目录中的工具
		local tool_files=$(find /tmp /var/tmp /dev/shm -name "*$tool*" -type f -executable 2>/dev/null)
		if [[ -n "$tool_files" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 在临时目录中发现网络工具 ($tool):"
			echo "$tool_files" | while read -r file; do
				echo -e "  ${YELLOW}→${NC} $file"
				((tools_in_tmp++))
			done
		fi
	done
	
	if [[ $tools_in_tmp -gt 0 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 临时目录中的网络工具可能用于反弹shell"
	else
		echo -e "${GREEN}[SUCC]${NC} 临时目录中未发现可疑的网络工具"
	fi
	
	# 5. 检查脚本文件中的反弹shell代码
	echo -e "${YELLOW}[INFO] 检查脚本文件中的反弹shell代码:${NC}"
	log_message "INFO" "检查脚本文件中的反弹shell代码"
	
	local script_dirs=("/tmp" "/var/tmp" "/dev/shm" "/home" "/root")
	local script_found=0
	
	for script_dir in "${script_dirs[@]}"; do
		if [[ -d "$script_dir" ]]; then
			local suspicious_scripts=$(find "$script_dir" -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -type f 2>/dev/null | head -20)
			if [[ -n "$suspicious_scripts" ]]; then
				echo "$suspicious_scripts" | while read -r script; do
					local reverse_code=$(grep -E "(socket.*connect|exec.*>/dev/tcp|bash.*-i.*>&|nc.*-e)" "$script" 2>/dev/null)
					if [[ -n "$reverse_code" ]]; then
						echo -e "${RED}[WARN]${NC} 脚本文件包含反弹shell代码: $script"
						echo "$reverse_code" | while read -r code; do
							echo -e "  ${RED}→${NC} $code"
							log_message "WARN" "脚本反弹shell代码: $script - $code" "reverseShellCheck"
							((script_found++))
						done
					fi
				done
			fi
		fi
	done
	
	if [[ $script_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 脚本文件中未发现反弹shell代码"
	fi
	
	# 6. 检查环境变量中的可疑内容
	echo -e "${YELLOW}[INFO] 检查环境变量中的可疑内容:${NC}"
	local suspicious_env=$(env | grep -E "(bash.*-i|nc.*-e|/dev/tcp|socket.*connect)" 2>/dev/null)
	if [[ -n "$suspicious_env" ]]; then
		echo -e "${RED}[WARN]${NC} 环境变量中发现可疑内容:"
		echo "$suspicious_env" | while read -r env_var; do
			echo -e "  ${RED}→${NC} $env_var"
			log_message "WARN" "环境变量反弹shell: $env_var" "reverseShellCheck"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 环境变量检查正常"
	fi
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - REVERSESHELL" "反弹shell检测模块" "END" "$execution_time"
	
	printf "\n"
}

# 增强型恶意软件检测 【重构完成】
virusCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - ENHANCED_VIRUS" "增强型恶意软件检测模块" "START"
	
	echo -e "${GREEN}[SUCC]${NC} 增强型恶意软件检测模块开始执行"
	echo -e "${BLUE}[INFO]${NC} 检测类型: 恶意进程、挖矿木马、文件威胁、网络异常、持久化机制"
	echo ""
	
	# 执行各项恶意软件检测 (合并原有功能和挖矿检测)
	enhanced_process_check     # 合并 virus_process_check + mining_process_detection
	enhanced_file_check        # 合并 virus_file_check + mining_file_detection
	enhanced_network_check     # 合并 virus_network_check + mining_network_detection
	enhanced_persistence_check # 合并 virus_persistence_check + mining_config_detection
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - ENHANCED_VIRUS" "增强型恶意软件检测模块" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} 增强型恶意软件检测模块执行完成"
	printf "\n"
}

# 统一的CPU检测函数 (消除重复代码)
unified_cpu_check() {
	local mode="${1:-general}"      # general/malware/mining
	local threshold="${2:-20}"      # CPU阈值百分比
	local count="${3:-10}"          # 显示数量
	
	local high_cpu_procs=$(ps aux --sort=-%cpu | head -$((count+1)) | awk "NR>1 && \$3>$threshold {print \$0}")
	
	if [[ -n "$high_cpu_procs" ]]; then
		case "$mode" in
			"malware")
				echo -e "${YELLOW}[NOTE]${NC} 高CPU占用进程(>${threshold}%) - 恶意软件检测模式:"
				;;
			"mining")
				echo -e "${RED}[WARN]${NC} 高CPU占用进程(>${threshold}%) - 可能的挖矿活动:"
				;;
			*)
				echo -e "${YELLOW}[NOTE]${NC} 高CPU占用进程(>${threshold}%):"
				;;
		esac
		
		echo "$high_cpu_procs" | while read -r proc; do
			local cpu_usage=$(echo "$proc" | awk '{print $3}')
			local process_name=$(echo "$proc" | awk '{print $11}')
			local pid=$(echo "$proc" | awk '{print $2}')
			echo -e "  ${YELLOW}→${NC} PID:$pid CPU:${cpu_usage}% - $process_name"
		done
		
		# 特殊模式下的额外检查
		if [[ "$mode" == "malware" || "$mode" == "mining" ]]; then
			local suspicious_count=$(echo "$high_cpu_procs" | wc -l)
			if [[ $suspicious_count -gt 3 ]]; then
				echo -e "${RED}[WARN]${NC} 发现${suspicious_count}个高CPU进程，建议进一步调查"
				log_message "WARN" "发现${suspicious_count}个高CPU进程" "virusCheck"
			fi
		fi
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现异常的高CPU占用进程(>${threshold}%)"
	fi
}

# 增强型进程检测 (合并原virus_process_check + mining_process_detection)
enhanced_process_check() {
	echo -e "${BLUE}[INFO]${NC} 正在执行增强型进程威胁检测..."
	
	# 合并的恶意进程特征库 (原有 + 挖矿专项 + LinuxCheck.sh补充)
	local malicious_processes=(
		# 知名挖矿软件 (合并两个列表)
		"xmrig" "xmr-stak" "cpuminer" "minerd" "ccminer" "sgminer" "cgminer" "ethminer"
		"cryptonight" "monero" "bitcoin" "ethereum" "zcash" "nicehash" "stratum"
		# 伪装挖矿进程 (LinuxCheck.sh增强)
		"systemctI" "kworkerds" "init10\.cfg" "wl\.conf" "crond64" "watchbog" "sustse" "donate" "proxkekman"
		"test\.conf" "/var/tmp/apple" "/var/tmp/big" "/var/tmp/small" "/var/tmp/cat" "/var/tmp/dog"
		"/var/tmp/mysql" "/var/tmp/sishen" "ubyx" "cpu\.c" "tes\.conf" "psping" "/var/tmp/java-c"
		"pscf" "sustes" "suppoie" "ririg" "/var/tmp/ntpd" "/var/tmp/ntp" "/var/tmp/qq" "/tmp/qq"
		"/var/tmp/aa" "gg1\.conf" "hh1\.conf" "apaqi" "dajiba" "/var/tmp/look" "/var/tmp/nginx"
		"dd1\.conf" "kkk1\.conf" "ttt1\.conf" "ooo1\.conf" "ppp1\.conf" "lll1\.conf" "yyy1\.conf"
		"1111\.conf" "2221\.conf" "dk1\.conf" "kd1\.conf" "mao1\.conf" "YB1\.conf" "2Ri1\.conf" "3Gu1\.conf"
		"crant" "linuxs" "linuxl" "Linux" "crawler\.weibo" "gpg-daemon" "jobs\.flu\.cc" "cranberry"
		"start\.sh" "watch\.sh" "krun\.sh" "killTop\.sh" "/60009" "ssh_deny\.sh" "clean\.sh"
		"\./over" "mrx1" "redisscan" "ebscan" "barad_agent" "\.sr0" "clay" "udevs" "\.sshd"
		"/tmp/init" "xmr" "xig" "ddgs" "hashvault" "geqn" "\.kthreadd" "httpdz" "pastebin\.com"
		"sobot\.com" "kerbero" "2t3ik" "qW3xt" "ztctb" "i2pd"
		# WorkMiner专项 (LinuxCheck.sh新增)
		"work32" "work64" "/tmp/secure\.sh" "/tmp/auth\.sh"
		# Ntpclient专项 (LinuxCheck.sh新增)
		"ntpclient" "Mozz"
		# 挖矿池相关 (新增)
		"pool\.minergate\.com" "stratum\+tcp" "mining\.pool" "xmrpool" "moneropool"
		# 远控木马
		"gh0st" "poison" "pcshare" "gray" "htran" "lcx"
		# 后门程序
		"nc\.traditional" "ncat" "socat" "netcat" "backdoor"
		# 恶意脚本
		"\.sh$" "python.*base64" "perl.*socket" "bash.*dev"
	)
	
	echo -e "${BLUE}[INFO]${NC} 检查恶意进程特征 (${#malicious_processes[@]}种模式)..."
	local total_found=0
	
	for process_pattern in "${malicious_processes[@]}"; do
		local suspicious_procs=$(ps aux | grep -v grep | grep -i -E "$process_pattern")
		if [[ -n "$suspicious_procs" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑进程 ($process_pattern):"
			echo "$suspicious_procs" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "发现可疑进程: $proc" "virusCheck"
				((total_found++))
			done
		fi
	done
	
	if [[ $total_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的恶意进程特征"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $total_found 个可疑进程"
	fi
	
	# 统一的高CPU检测 (智能阈值)
	echo -e "${BLUE}[INFO]${NC} 检查高CPU占用进程..."
	unified_cpu_check "malware" 50 15  # 阈值50%, 显示前15个, 恶意软件模式
	
	# 检查异常网络连接的进程
	echo -e "${BLUE}[INFO]${NC} 检查异常网络连接..."
	local suspicious_connections=$(netstat -antp 2>/dev/null | grep ESTABLISHED | awk '{print $7}' | grep -v '-' | sort | uniq -c | sort -rn | head -10)
	if [[ -n "$suspicious_connections" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 网络连接数量排序(前10):"
		echo "$suspicious_connections" | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现异常的网络连接模式"
	fi
}

# 增强型文件检测 (合并原virus_file_check + mining_file_detection)
enhanced_file_check() {
	echo -e "${BLUE}[INFO]${NC} 正在执行增强型文件威胁检测..."
	
	# 统一的文件检测函数调用
	unified_file_check "/tmp" "/var/tmp" "/dev/shm" "/home/*/.ssh" "/usr/bin" "/usr/sbin" "/bin" "/sbin"
	
	# 专项挖矿文件检测
	mining_specific_file_check
	
	# 恶意脚本内容检测
	malicious_script_content_check
}

# 统一的文件检测函数 (消除重复代码)
unified_file_check() {
	local paths=("$@")
	
	echo -e "${BLUE}[INFO]${NC} 检查可疑文件路径 (${#paths[@]}个目录)..."
	
	for path in "${paths[@]}"; do
		if [[ -d "$path" ]] || [[ "$path" == *"*"* ]]; then
			echo -e "${YELLOW}[检查路径]${NC} $path"
			
			# 检查最近修改的可执行文件 (7天内)
			local recent_executables=$(find $path -type f -executable -mtime -7 2>/dev/null | head -20)
			if [[ -n "$recent_executables" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 7天内修改的可执行文件:"
				echo "$recent_executables" | while read -r file; do
					local size=$(du -h "$file" 2>/dev/null | cut -f1)
					local mtime=$(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null)
					echo -e "  ${YELLOW}→${NC} $file ($size, $mtime)"
				done
			fi
			
			# 检查异常大小的可执行文件 (>10MB)
			local large_executables=$(find $path -type f -executable -size +10M 2>/dev/null | head -10)
			if [[ -n "$large_executables" ]]; then
				echo -e "${RED}[WARN]${NC} 异常大小的可执行文件(>10MB):"
				echo "$large_executables" | while read -r file; do
					local size=$(du -h "$file" 2>/dev/null | cut -f1)
					echo -e "  ${RED}→${NC} $file ($size)"
					log_message "WARN" "发现异常大小可执行文件: $file ($size)" "virusCheck"
				done
			fi
			
			# 检查隐藏的可执行文件
			local hidden_executables=$(find $path -type f -name ".*" -executable 2>/dev/null | head -10)
			if [[ -n "$hidden_executables" ]]; then
				echo -e "${RED}[WARN]${NC} 隐藏的可执行文件:"
				echo "$hidden_executables" | while read -r file; do
					local size=$(du -h "$file" 2>/dev/null | cut -f1)
					echo -e "  ${RED}→${NC} $file ($size)"
					log_message "WARN" "发现隐藏可执行文件: $file" "virusCheck"
				done
			fi
		fi
	done
}

# 专项挖矿文件检测
mining_specific_file_check() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿相关文件特征..."
	
	# 挖矿文件名模式 (合并原有检测 + LinuxCheck.sh补充)
	local mining_file_patterns=(
		# 知名挖矿软件
		".*xmrig.*" ".*xmr-stak.*" ".*cpuminer.*" ".*minerd.*"
		".*systemctI.*" ".*kworkerds.*" ".*watchbog.*" ".*sustse.*"
		".*cryptonight.*" ".*monero.*" ".*zcash.*" ".*ethereum.*"
		".*miner\.sh.*" ".*mining.*" ".*pool.*" ".*stratum.*"
		".*\.mine.*" ".*\.crypto.*" ".*\.coin.*"
		# LinuxCheck.sh补充的挖矿文件特征
		".*init10\.cfg.*" ".*wl\.conf.*" ".*crond64.*" ".*donate.*" ".*proxkekman.*"
		".*suppoie.*" ".*ririg.*" ".*xmr.*" ".*xig.*" ".*ddgs.*" ".*hashvault.*"
		".*kthreadd.*" ".*httpdz.*" ".*kerbero.*" ".*2t3ik.*" ".*qW3xt.*" ".*ztctb.*"
		# WorkMiner专项文件
		".*work32.*" ".*work64.*" 
		# Ntpclient专项文件
		".*ntpclient.*" ".*Mozz.*"
	)
	
	local mining_files_found=0
	for pattern in "${mining_file_patterns[@]}"; do
		local mining_files=$(find / -type f -regextype posix-extended -regex "$pattern" ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" 2>/dev/null | head -5)
		if [[ -n "$mining_files" ]]; then
			echo -e "${RED}[WARN]${NC} 发现挖矿相关文件 ($pattern):"
			echo "$mining_files" | while read -r file; do
				local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
				local file_time=$(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null)
				echo -e "  ${RED}→${NC} $file ($file_size, $file_time)"
				log_message "WARN" "发现挖矿文件: $file" "virusCheck"
				((mining_files_found++))
			done
		fi
	done
	
	# 专项挖矿木马检测 (LinuxCheck.sh补充)
	echo -e "${BLUE}[INFO]${NC} 执行专项挖矿木马检测..."
	
	# Ntpclient挖矿木马检测
	echo -e "${YELLOW}[检查]${NC} Ntpclient挖矿木马..."
	local ntpclient_files=$(ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)
	if [[ -n "$ntpclient_files" ]]; then
		echo -e "${RED}[WARN]${NC} 发现Ntpclient挖矿木马特征文件:"
		echo "$ntpclient_files" | while read -r line; do
			echo -e "  ${RED}→${NC} $line"
			log_message "WARN" "Ntpclient挖矿木马文件: $line" "virusCheck"
			((mining_files_found++))
		done
	fi
	
	# WorkMiner挖矿木马检测
	echo -e "${YELLOW}[检查]${NC} WorkMiner挖矿木马..."
	local workminer_files=$(ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)
	if [[ -n "$workminer_files" ]]; then
		echo -e "${RED}[WARN]${NC} 发现WorkMiner挖矿木马特征文件:"
		echo "$workminer_files" | while read -r line; do
			echo -e "  ${RED}→${NC} $line"
			log_message "WARN" "WorkMiner挖矿木马文件: $line" "virusCheck"
			((mining_files_found++))
		done
	fi
	
	if [[ $mining_files_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的挖矿文件特征"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $mining_files_found 个挖矿相关文件"
	fi
}

# 恶意脚本内容检测
malicious_script_content_check() {
	echo -e "${BLUE}[INFO]${NC} 检查脚本文件恶意内容..."
	
	# 恶意内容特征 (合并原有 + 挖矿特征)
	local malicious_strings=(
		# 网络通信特征
		"socket.*connect" "urllib.*request" "requests\.get" "wget.*http" "curl.*http"
		# 加密特征
		"base64.*decode" "rot13" "xor.*key" "aes.*encrypt" "des.*crypt"
		# 系统调用特征
		"system\(" "exec\(" "popen\(" "fork\(" "subprocess\."
		# 持久化特征
		"crontab.*-e" "systemctl.*enable" "service.*start" "rc\.local"
		# 挖矿特征 (新增)
		"stratum\+tcp" "mining\.pool" "xmr.*pool" "crypto.*wallet"
	)
	
	# 检查临时目录下的脚本文件
	local script_dirs=("/tmp" "/var/tmp" "/dev/shm")
	local total_suspicious=0
	
	for script_dir in "${script_dirs[@]}"; do
		local temp_scripts=$(find "$script_dir" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.js" \) 2>/dev/null | head -10)
		if [[ -n "$temp_scripts" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} $script_dir 目录下的脚本文件:"
			echo "$temp_scripts" | while read -r script; do
				echo -e "  ${YELLOW}→${NC} $script"
				local suspicious_patterns=0
				
				# 检查脚本内容中的恶意特征
				for pattern in "${malicious_strings[@]}"; do
					if grep -q -E "$pattern" "$script" 2>/dev/null; then
						echo -e "    ${RED}[WARN]${NC} 包含可疑内容: $pattern"
						log_message "WARN" "脚本文件包含可疑内容: $script - $pattern" "virusCheck"
						((suspicious_patterns++))
						((total_suspicious++))
					fi
				done
				
				if [[ $suspicious_patterns -gt 2 ]]; then
					echo -e "    ${RED}[CRITICAL]${NC} 该脚本包含${suspicious_patterns}种可疑特征，高度可疑！"
					log_message "CRITICAL" "高度可疑脚本: $script (${suspicious_patterns}种特征)" "virusCheck"
				fi
			done
		fi
	done
	
	if [[ $total_suspicious -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现包含恶意内容的脚本文件"
	else
		echo -e "${RED}[WARN]${NC} 发现 $total_suspicious 个可疑的脚本内容特征"
	fi
}

# 增强型网络检测 (合并原virus_network_check + mining_network_detection)
enhanced_network_check() {
	echo -e "${BLUE}[INFO]${NC} 正在执行增强型网络威胁检测..."
	
	# 统一的端口检测 (合并挖矿池 + 远控 + 代理端口)
	unified_port_check
	
	# DNS和域名检测
	dns_threat_check
	
	# 网络连接异常分析
	network_anomaly_check
}

# 统一的端口检测函数
unified_port_check() {
	echo -e "${BLUE}[INFO]${NC} 检查可疑端口连接..."
	
	# 合并的可疑端口列表 (挖矿池 + 远控 + 代理)
	local suspicious_ports=(
		# 挖矿池端口 (合并原有检测)
		"3333" "4444" "5555" "6666" "7777" "8888" "9999"
		"3367" "3377" "3636" "5730" "5740" "6688" "8008"
		"8118" "8220" "9008" "9221" "13333" "13531" "45560"
		"14444" "17777" "19999"
		# 远控端口
		"1234" "12345" "54321" "31337" "65535"
		# 代理隧道端口
		"1080" "7001" "8080" "8443" "9050" "9150"
	)
	
	local total_suspicious=0
	for port in "${suspicious_ports[@]}"; do
		local connections=$(netstat -an 2>/dev/null | grep ":$port " | grep ESTABLISHED)
		if [[ -n "$connections" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑端口连接 ($port):"
			echo "$connections" | while read -r conn; do
				echo -e "  ${RED}→${NC} $conn"
				log_message "WARN" "发现可疑端口连接: $conn" "virusCheck"
				((total_suspicious++))
			done
		fi
	done
	
	if [[ $total_suspicious -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现已知的可疑端口连接"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $total_suspicious 个可疑端口连接"
	fi
}

# DNS和域名威胁检测
dns_threat_check() {
	echo -e "${BLUE}[INFO]${NC} 检查DNS和域名威胁..."
	
	# 可疑域名特征 (合并挖矿 + C&C)
	local suspicious_domains=(
		# 挖矿池域名特征
		"pool" "mine" "coin" "crypto" "hash" "stratum" "xmr" "monero"
		"minergate" "nanopool" "f2pool" "antpool" "btcpool"
		# C&C域名特征
		"dyndns" "no-ip" "ddns" "freedns" "3322" "oicp"
		# 恶意软件域名特征
		"malware" "trojan" "backdoor" "botnet"
	)
	
	# 检查/etc/hosts文件
	if [[ -f "/etc/hosts" ]]; then
		local hosts_suspicious=$(grep -v "^#" /etc/hosts 2>/dev/null | grep -E "($(IFS='|'; echo "${suspicious_domains[*]}"))")
		if [[ -n "$hosts_suspicious" ]]; then
			echo -e "${RED}[WARN]${NC} /etc/hosts中的可疑域名:"
			echo "$hosts_suspicious" | while read -r entry; do
				echo -e "  ${RED}→${NC} $entry"
				log_message "WARN" "发现可疑hosts条目: $entry" "virusCheck"
			done
		else
			echo -e "${GREEN}[SUCC]${NC} /etc/hosts文件未发现可疑域名"
		fi
	fi
	
	# 检查DNS查询历史 (如果有dig命令)
	if command -v dig >/dev/null 2>&1; then
		echo -e "${BLUE}[INFO]${NC} DNS工具可用，可进行深度DNS检测"
	else
		echo -e "${YELLOW}[NOTE]${NC} 未找到dig命令，跳过DNS查询检测"
	fi
}

# 网络连接异常分析
network_anomaly_check() {
	echo -e "${BLUE}[INFO]${NC} 分析网络连接异常模式..."
	
	# 检查大量外联连接
	local external_connections=$(netstat -an 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1" | grep -v "::1" | wc -l)
	if [[ $external_connections -gt 50 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现大量外部连接 ($external_connections 个)，可能存在异常"
		log_message "WARN" "发现大量外部连接: $external_connections 个" "virusCheck"
	else
		echo -e "${GREEN}[SUCC]${NC} 外部连接数量正常 ($external_connections 个)"
	fi
	
	# 检查异常的监听端口
	local listening_ports=$(netstat -an 2>/dev/null | grep LISTEN | grep -v "127.0.0.1" | grep -v "::1" | wc -l)
	if [[ $listening_ports -gt 20 ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 发现较多监听端口 ($listening_ports 个)，建议检查"
		
		# 显示非标准监听端口
		local unusual_listeners=$(netstat -an 2>/dev/null | grep LISTEN | grep -v -E "(22|80|443|25|53|21|23)" | head -10)
		if [[ -n "$unusual_listeners" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 非标准监听端口:"
			echo "$unusual_listeners" | while read -r listener; do
				echo -e "  ${YELLOW}→${NC} $listener"
			done
		fi
	else
		echo -e "${GREEN}[SUCC]${NC} 监听端口数量正常 ($listening_ports 个)"
	fi
}

# 增强型持久化检测 (合并原virus_persistence_check + mining_config_detection)
enhanced_persistence_check() {
	echo -e "${BLUE}[INFO]${NC} 正在执行增强型持久化威胁检测..."
	
	# 定时任务检测
	cron_threat_check
	
	# 系统服务检测
	service_threat_check
	
	# 启动脚本检测
	startup_threat_check
	
	# 挖矿配置文件检测 (合并mining_config_detection)
	mining_config_threat_check
}

# 定时任务威胁检测
cron_threat_check() {
	echo -e "${BLUE}[INFO]${NC} 检查定时任务威胁..."
	
	# 检查当前用户的定时任务
	local suspicious_cron=$(crontab -l 2>/dev/null | grep -v "^#" | grep -E "(wget|curl|python|bash|sh|miner|crypto|coin)")
	if [[ -n "$suspicious_cron" ]]; then
		echo -e "${RED}[WARN]${NC} 发现可疑定时任务:"
		echo "$suspicious_cron" | while read -r cron; do
			echo -e "  ${RED}→${NC} $cron"
			log_message "WARN" "发现可疑定时任务: $cron" "virusCheck"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 当前用户定时任务正常"
	fi
	
	# 检查系统级定时任务
	local system_cron_dirs=("/etc/crontab" "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly")
	for cron_dir in "${system_cron_dirs[@]}"; do
		if [[ -f "$cron_dir" ]] || [[ -d "$cron_dir" ]]; then
			local system_suspicious=$(find "$cron_dir" -type f 2>/dev/null | xargs grep -l -E "(wget|curl|python.*socket|miner|crypto)" 2>/dev/null)
			if [[ -n "$system_suspicious" ]]; then
				echo -e "${RED}[WARN]${NC} 系统定时任务中发现可疑内容 ($cron_dir):"
				echo "$system_suspicious" | while read -r file; do
					echo -e "  ${RED}→${NC} $file"
					log_message "WARN" "系统定时任务可疑文件: $file" "virusCheck"
				done
			fi
		fi
	done
}

# 系统服务威胁检测
service_threat_check() {
	echo -e "${BLUE}[INFO]${NC} 检查系统服务威胁..."
	
	if command -v systemctl >/dev/null 2>&1; then
		# 检查可疑的活动服务 (扩展特征)
		local suspicious_services=$(systemctl list-units --type=service --state=active | grep -E "(miner|crypto|coin|backdoor|trojan|xmrig|monero|bitcoin|ethereum)")
		if [[ -n "$suspicious_services" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑系统服务:"
			echo "$suspicious_services" | while read -r service; do
				echo -e "  ${RED}→${NC} $service"
				log_message "WARN" "发现可疑系统服务: $service" "virusCheck"
			done
		else
			echo -e "${GREEN}[SUCC]${NC} 未发现可疑的活动系统服务"
		fi
		
		# 检查最近启用的服务
		local recent_services=$(systemctl list-unit-files --type=service | grep enabled | grep -E "(miner|crypto|coin|mining)" 2>/dev/null)
		if [[ -n "$recent_services" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现已启用的可疑服务:"
			echo "$recent_services" | while read -r service; do
				echo -e "  ${YELLOW}→${NC} $service"
			done
		fi
	else
		echo -e "${YELLOW}[NOTE]${NC} systemctl不可用，跳过systemd服务检查"
	fi
}

# 启动脚本威胁检测
startup_threat_check() {
	echo -e "${BLUE}[INFO]${NC} 检查启动脚本威胁..."
	
	# 扩展的启动脚本路径
	local startup_paths=(
		"/etc/rc.local"
		"/etc/init.d"
		"/etc/systemd/system"
		"/home/*/.bashrc"
		"/home/*/.bash_profile"
		"/home/*/.profile"
		"/root/.bashrc"
		"/root/.bash_profile"
		"/etc/bash.bashrc"
		"/etc/profile"
	)
	
	local total_suspicious=0
	for path in "${startup_paths[@]}"; do
		if [[ -f "$path" ]] || [[ -d "$path" ]]; then
			# 扩展的可疑内容模式 (包含挖矿特征)
			local suspicious_startup=$(find $path -type f 2>/dev/null | xargs grep -l -E "(wget|curl|python.*socket|bash.*dev|miner|crypto|coin|stratum|xmrig)" 2>/dev/null)
			if [[ -n "$suspicious_startup" ]]; then
				echo -e "${RED}[WARN]${NC} 启动脚本中的可疑内容 ($path):"
				echo "$suspicious_startup" | while read -r file; do
					echo -e "  ${RED}→${NC} $file"
					log_message "WARN" "启动脚本可疑文件: $file" "virusCheck"
					((total_suspicious++))
				done
			fi
		fi
	done
	
	if [[ $total_suspicious -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 启动脚本检查正常"
	else
		echo -e "${RED}[WARN]${NC} 发现 $total_suspicious 个可疑启动脚本"
	fi
}

# 挖矿配置文件威胁检测 (合并mining_config_detection)
mining_config_threat_check() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿配置文件威胁..."
	
	# 挖矿配置文件特征
	local mining_config_patterns=(
		"pool.*stratum" "wallet.*address" "mining.*config" "xmr.*config"
		"monero.*conf" "bitcoin.*conf" "ethereum.*conf" "zcash.*conf"
		"miner.*json" "pool.*json" "crypto.*json"
	)
	
	# 常见配置文件路径
	local config_paths=("/etc" "/opt" "/usr/local" "/home" "/root" "/tmp" "/var/tmp")
	local mining_configs_found=0
	
	for config_path in "${config_paths[@]}"; do
		for pattern in "${mining_config_patterns[@]}"; do
			local config_files=$(find "$config_path" -type f -name "*.conf" -o -name "*.json" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | xargs grep -l -E "$pattern" 2>/dev/null | head -5)
			if [[ -n "$config_files" ]]; then
				echo -e "${RED}[WARN]${NC} 发现挖矿配置文件 ($pattern):"
				echo "$config_files" | while read -r config; do
					echo -e "  ${RED}→${NC} $config"
					log_message "WARN" "发现挖矿配置文件: $config" "virusCheck"
					((mining_configs_found++))
				done
			fi
		done
	done
	
	if [[ $mining_configs_found -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现挖矿配置文件"
	else
		echo -e "${RED}[WARN]${NC} 总计发现 $mining_configs_found 个挖矿配置文件"
	fi
}

# 内存排查 【重构完成】
memInfoCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - MEMORY" "内存分析模块" "START"
	
	echo -e "${GREEN}[SUCC]${NC} 内存分析模块开始执行"
	echo -e "${BLUE}[INFO]${NC} 检测类型: 进程内存映射、内存马检测、异常内存使用、隐藏进程"
	echo ""
	
	# 1. 进程内存映射分析
	memory_mapping_analysis
	
	# 2. 内存马检测
	memory_malware_detection
	
	# 3. 异常内存使用分析
	memory_usage_analysis
	
	# 4. 隐藏进程检测 (基于/proc与ps的差异)
	hidden_process_detection
	
	# 5. 内存中的可疑字符串检测
	memory_string_analysis
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - MEMORY" "内存分析模块" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} 内存分析模块执行完成"
	printf "\n"
}

# 进程内存映射分析
memory_mapping_analysis() {
	echo -e "${BLUE}[INFO]${NC} 正在分析进程内存映射..."
	
	# 检查进程内存映射中的异常特征
	local suspicious_mappings=0
	local high_cpu_pids=$(ps aux --sort=-%cpu | head -10 | awk 'NR>1 {print $2}')
	
	if [[ -n "$high_cpu_pids" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 分析高CPU进程的内存映射:"
		echo "$high_cpu_pids" | while read -r pid; do
			if [[ -f "/proc/$pid/maps" ]]; then
				local process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
				echo -e "  ${YELLOW}→${NC} PID:$pid ($process_name)"
				
				# 检查可执行内存区域
				local exec_regions=$(grep "r-xp" "/proc/$pid/maps" 2>/dev/null | wc -l)
				local rwx_regions=$(grep "rwxp" "/proc/$pid/maps" 2>/dev/null)
				
				if [[ -n "$rwx_regions" ]]; then
					echo -e "    ${RED}[WARN]${NC} 发现可读写执行内存区域:"
					echo "$rwx_regions" | while read -r region; do
						echo -e "      ${RED}→${NC} $region"
						log_message "WARN" "进程$pid异常内存映射: $region" "memInfoCheck"
						((suspicious_mappings++))
					done
				fi
				
				# 检查删除文件的内存映射 (内存马特征)
				local deleted_mappings=$(grep "deleted" "/proc/$pid/maps" 2>/dev/null)
				if [[ -n "$deleted_mappings" ]]; then
					echo -e "    ${RED}[WARN]${NC} 发现已删除文件的内存映射 (可能的内存马):"
					echo "$deleted_mappings" | while read -r mapping; do
						echo -e "      ${RED}→${NC} $mapping"
						log_message "WARN" "进程$pid内存马特征: $mapping" "memInfoCheck"
						((suspicious_mappings++))
					done
				fi
				
				# 检查堆栈异常权限
				local heap_stack_rwx=$(grep -E "(heap|stack)" "/proc/$pid/maps" 2>/dev/null | grep "rwxp")
				if [[ -n "$heap_stack_rwx" ]]; then
					echo -e "    ${RED}[WARN]${NC} 堆栈区域具有执行权限 (异常):"
					echo "$heap_stack_rwx" | while read -r region; do
						echo -e "      ${RED}→${NC} $region"
						log_message "WARN" "进程$pid堆栈执行权限异常: $region" "memInfoCheck"
					done
				fi
			fi
		done
	fi
	
	if [[ $suspicious_mappings -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 进程内存映射检查正常"
	else
		echo -e "${RED}[WARN]${NC} 发现 $suspicious_mappings 个可疑内存映射"
	fi
}

# 内存马检测
memory_malware_detection() {
	echo -e "${BLUE}[INFO]${NC} 正在检测内存马..."
	
	# 1. 检查无文件进程 (进程在运行但二进制文件已被删除)
	echo -e "${YELLOW}[INFO] 检查无文件进程:${NC}"
	local deleted_processes=0
	
	local all_pids=$(ps aux --no-headers | awk '{print $2}')
	echo "$all_pids" | while read -r pid; do
		if [[ -d "/proc/$pid" ]]; then
			local exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null)
			if [[ "$exe_link" == *"deleted"* ]]; then
				local process_info=$(ps -p "$pid" -o pid,ppid,user,comm --no-headers 2>/dev/null)
				echo -e "${RED}[WARN]${NC} 发现无文件进程 (可能的内存马):"
				echo -e "  ${RED}→${NC} PID:$pid 可执行文件已删除: $exe_link"
				echo -e "  ${RED}→${NC} 进程信息: $process_info"
				log_message "WARN" "内存马进程: PID $pid, $exe_link" "memInfoCheck"
				((deleted_processes++))
			fi
		fi
	done
	
	# 2. 检查进程命令行与可执行文件不匹配
	echo -e "${YELLOW}[INFO] 检查进程命令行异常:${NC}"
	local cmdline_anomalies=0
	
	echo "$all_pids" | while read -r pid; do
		if [[ -f "/proc/$pid/cmdline" ]]; then
			local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
			local exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null)
			
			if [[ -n "$cmdline" ]] && [[ -n "$exe_link" ]]; then
				# 检查命令行是否包含可疑内容
				if echo "$cmdline" | grep -qE "(bash.*-i|nc.*-e|python.*socket|perl.*socket|/dev/tcp)"; then
					echo -e "${RED}[WARN]${NC} 发现可疑进程命令行:"
					echo -e "  ${RED}→${NC} PID:$pid 命令行: $cmdline"
					echo -e "  ${RED}→${NC} 可执行文件: $exe_link"
					log_message "WARN" "可疑进程命令行: PID $pid, $cmdline" "memInfoCheck"
					((cmdline_anomalies++))
				fi
			fi
		fi
	done
	
	# 3. 检查进程的文件描述符异常
	echo -e "${YELLOW}[INFO] 检查进程文件描述符:${NC}"
	local fd_anomalies=0
	
	# 检查高CPU进程的文件描述符
	local high_cpu_pids=$(ps aux --sort=-%cpu | head -5 | awk 'NR>1 {print $2}')
	echo "$high_cpu_pids" | while read -r pid; do
		if [[ -d "/proc/$pid/fd" ]]; then
			local process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
			local fd_count=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
			
			# 检查是否有异常多的文件描述符
			if [[ $fd_count -gt 100 ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 进程 $pid ($process_name) 打开了 $fd_count 个文件描述符"
			fi
			
			# 检查可疑的网络连接文件描述符
			local suspicious_fds=$(ls -la "/proc/$pid/fd" 2>/dev/null | grep -E "socket:|pipe:" | head -5)
			if [[ -n "$suspicious_fds" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 进程 $pid ($process_name) 的网络/管道连接:"
				echo "$suspicious_fds" | while read -r fd; do
					echo -e "  ${YELLOW}→${NC} $fd"
				done
			fi
		fi
	done
	
	if [[ $deleted_processes -eq 0 ]] && [[ $cmdline_anomalies -eq 0 ]] && [[ $fd_anomalies -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 内存马检测正常"
	else
		echo -e "${RED}[WARN]${NC} 发现可疑的内存马特征"
	fi
}

# 异常内存使用分析
memory_usage_analysis() {
	echo -e "${BLUE}[INFO]${NC} 正在分析内存使用情况..."
	
	# 1. 系统内存总体状况
	echo -e "${YELLOW}[INFO] 系统内存状况:${NC}"
	if [[ -f "/proc/meminfo" ]]; then
		local mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
		local mem_free=$(grep "MemFree" /proc/meminfo | awk '{print $2}')
		local mem_available=$(grep "MemAvailable" /proc/meminfo | awk '{print $2}')
		local buffers=$(grep "Buffers" /proc/meminfo | awk '{print $2}')
		local cached=$(grep "Cached" /proc/meminfo | awk '{print $2}')
		
		local mem_used=$((mem_total - mem_free - buffers - cached))
		local mem_usage_percent=$(( (mem_used * 100) / mem_total ))
		
		echo -e "  ${YELLOW}→${NC} 总内存: $((mem_total / 1024))MB"
		echo -e "  ${YELLOW}→${NC} 已用内存: $((mem_used / 1024))MB ($mem_usage_percent%)"
		echo -e "  ${YELLOW}→${NC} 可用内存: $((mem_available / 1024))MB"
		
		if [[ $mem_usage_percent -gt 90 ]]; then
			echo -e "  ${RED}[WARN]${NC} 内存使用率过高 ($mem_usage_percent%)，可能存在内存泄漏"
			log_message "WARN" "内存使用率过高: $mem_usage_percent%" "memInfoCheck"
		elif [[ $mem_usage_percent -gt 80 ]]; then
			echo -e "  ${YELLOW}[NOTE]${NC} 内存使用率较高 ($mem_usage_percent%)"
		else
			echo -e "  ${GREEN}[SUCC]${NC} 内存使用率正常 ($mem_usage_percent%)"
		fi
	fi
	
	# 2. 高内存占用进程分析
	echo -e "${YELLOW}[INFO] 高内存占用进程:${NC}"
	local high_mem_processes=$(ps aux --sort=-%mem | head -10 | awk 'NR>1 {print $2, $4, $11}')
	if [[ -n "$high_mem_processes" ]]; then
		echo "$high_mem_processes" | while read -r pid mem_percent cmd; do
			echo -e "  ${YELLOW}→${NC} PID:$pid 内存:${mem_percent}% 命令:$cmd"
			
			# 检查内存使用超过10%的进程
			if (( $(echo "$mem_percent > 10" | bc -l) )); then
				echo -e "    ${YELLOW}[NOTE]${NC} 高内存占用进程，建议检查"
				
				# 检查进程的内存映射详情
				if [[ -f "/proc/$pid/status" ]]; then
					local vm_size=$(grep "VmSize" "/proc/$pid/status" 2>/dev/null | awk '{print $2, $3}')
					local vm_rss=$(grep "VmRSS" "/proc/$pid/status" 2>/dev/null | awk '{print $2, $3}')
					echo -e "    ${YELLOW}→${NC} 虚拟内存: $vm_size"
					echo -e "    ${YELLOW}→${NC} 物理内存: $vm_rss"
				fi
			fi
		done
	fi
	
	# 3. 检查内存碎片化
	echo -e "${YELLOW}[INFO] 内存碎片化检查:${NC}"
	if [[ -f "/proc/buddyinfo" ]]; then
		local buddy_info=$(cat /proc/buddyinfo | head -3)
		echo -e "  ${YELLOW}[NOTE]${NC} 内存伙伴系统信息:"
		echo "$buddy_info" | while read -r line; do
			echo -e "  ${YELLOW}→${NC} $line"
		done
	fi
}

# 隐藏进程检测 (基于/proc与ps的差异)
hidden_process_detection() {
	echo -e "${BLUE}[INFO]${NC} 正在检测隐藏进程..."
	
	# 获取/proc目录中的所有数字目录(PID)
	local proc_pids=$(ls -1 /proc | grep -E "^[0-9]+$" | sort -n)
	
	# 获取ps命令显示的所有PID
	local ps_pids=$(ps aux --no-headers | awk '{print $2}' | sort -n)
	
	# 比较两个列表，找出差异
	local hidden_pids=()
	local proc_count=0
	local ps_count=0
	
	# 计算进程数量
	proc_count=$(echo "$proc_pids" | wc -l)
	ps_count=$(echo "$ps_pids" | wc -l)
	
	echo -e "${YELLOW}[INFO] 进程统计:${NC}"
	echo -e "  ${YELLOW}→${NC} /proc目录中的进程: $proc_count 个"
	echo -e "  ${YELLOW}→${NC} ps命令显示的进程: $ps_count 个"
	
	# 查找在/proc中存在但ps中不存在的PID
	local hidden_count=0
	echo "$proc_pids" | while read -r pid; do
		if ! echo "$ps_pids" | grep -q "^$pid$"; then
			# 验证这个PID确实存在且不是内核线程
			if [[ -d "/proc/$pid" ]]; then
				local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
				local comm=$(cat "/proc/$pid/comm" 2>/dev/null)
				
				# 排除内核线程 (通常cmdline为空且comm在方括号中)
				if [[ -n "$cmdline" ]] || [[ "$comm" != *"["* ]]; then
					echo -e "${RED}[WARN]${NC} 发现隐藏进程:"
					echo -e "  ${RED}→${NC} PID: $pid"
					echo -e "  ${RED}→${NC} 命令: ${cmdline:-$comm}"
					
					# 获取更多信息
					local exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null)
					local cwd_link=$(readlink "/proc/$pid/cwd" 2>/dev/null)
					echo -e "  ${RED}→${NC} 可执行文件: ${exe_link:-未知}"
					echo -e "  ${RED}→${NC} 工作目录: ${cwd_link:-未知}"
					
					log_message "WARN" "发现隐藏进程: PID $pid, 命令: $cmdline" "memInfoCheck"
					((hidden_count++))
				fi
			fi
		fi
	done
	
	if [[ $hidden_count -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 未发现隐藏进程"
	else
		echo -e "${RED}[WARN]${NC} 发现 $hidden_count 个可能的隐藏进程"
	fi
}

# 内存中的可疑字符串检测
memory_string_analysis() {
	echo -e "${BLUE}[INFO]${NC} 正在分析内存中的可疑字符串..."
	
	# 检查高CPU进程的内存内容
	local high_cpu_pids=$(ps aux --sort=-%cpu | head -5 | awk 'NR>1 {print $2}')
	local suspicious_strings=0
	
	# 可疑字符串模式
	local malicious_patterns=(
		# 网络相关
		"socket.*connect" "bind.*listen" "reverse.*shell"
		# 加密相关
		"base64" "encrypt" "decrypt" "crypto"
		# 系统调用相关
		"system.*call" "exec.*shell" "fork.*process"
		# 恶意软件相关
		"backdoor" "trojan" "rootkit" "malware"
	)
	
	echo -e "${YELLOW}[INFO] 检查高CPU进程的内存环境变量:${NC}"
	echo "$high_cpu_pids" | while read -r pid; do
		if [[ -f "/proc/$pid/environ" ]]; then
			local process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
			local environ_content=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null)
			
			if [[ -n "$environ_content" ]]; then
				echo -e "  ${YELLOW}→${NC} PID:$pid ($process_name) 环境变量:"
				
				# 检查可疑的环境变量
				for pattern in "${malicious_patterns[@]}"; do
					local matches=$(echo "$environ_content" | grep -i -E "$pattern" 2>/dev/null)
					if [[ -n "$matches" ]]; then
						echo -e "    ${RED}[WARN]${NC} 发现可疑环境变量模式 ($pattern):"
						echo "$matches" | while read -r match; do
							echo -e "      ${RED}→${NC} $match"
							log_message "WARN" "进程$pid可疑环境变量: $match" "memInfoCheck"
							((suspicious_strings++))
						done
					fi
				done
				
				# 显示前几个环境变量作为参考
				echo "$environ_content" | head -5 | while read -r env_var; do
					if [[ -n "$env_var" ]]; then
						echo -e "    ${YELLOW}→${NC} $env_var"
					fi
				done
			fi
		fi
	done
	
	if [[ $suspicious_strings -eq 0 ]]; then
		echo -e "${GREEN}[SUCC]${NC} 内存字符串检查正常"
	else
		echo -e "${RED}[WARN]${NC} 发现 $suspicious_strings 个可疑内存字符串"
	fi
}

# 黑客工具排查 【完成】
hackerToolsCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - HACKERTOOLSCHECK" "黑客工具检查模块" "START"
	
	# 黑客工具排查
	echo -e "${YELLOW}正在检查全盘是否存在黑客工具[./checkrules/hackertoolslist.txt]:${NC}"  
	log_message "INFO" "正在检查全盘是否存在黑客工具"
	# hacker_tools_list="nc sqlmap nmap xray beef nikto john ettercap backdoor *proxy msfconsole msf *scan nuclei *brute* gtfo Titan zgrab frp* lcx *reGeorg nps spp suo5 sshuttle v2ray"
	# 从 hacker_tools_list 列表中取出一个工具名然后全盘搜索
	# hacker_tools_list=$(cat ./checkrules/hackertoolslist.txt)
	echo -e "${BLUE}[KNOW] 定义黑客工具列表文件hackertoolslist.txt,全盘搜索该列表中的工具名,如果存在则告警(工具文件可自行维护)${NC}"
	# log_message "INFO" "定义黑客工具列表文件hackertoolslist.txt,全盘搜索该列表中的工具名,如果存在则告警"
	hacker_tools_list=$(cat ${current_dir}/checkrules/hackertoolslist.txt 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "读取黑客工具列表文件失败" "hackerToolsCheck"
	fi
	for hacker_tool in $hacker_tools_list
	do
		findhackertool=$(find / -name $hacker_tool 2>/dev/null)
		if [ -n "$findhackertool" ];then
			(echo -e "${RED}[WARN] 发现全盘存在可疑黑客工具:$hacker_tool${NC}" && echo "$findhackertool")  
			log_message "INFO" "发现全盘存在可疑黑客工具:$hacker_tool"
		else
			echo -e "${GREEN}[SUCC] 未发现全盘存在可疑黑可工具:$hacker_tool${NC}"  
			log_message "INFO" "未发现全盘存在可疑黑客工具:$hacker_tool"
		fi
		printf "\n"  
	done
	
	# 常见黑客痕迹排查
	
	# 记录结束时间和性能统计
	end_time=$(date +%s)
	log_performance "hackerToolsCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - HACKERTOOLSCHECK" "黑客工具检查模块执行完成" "END"

}

# 内核排查 【完成】
kernelCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - KERNELCHECK" "内核检查模块" "START"
	
	# 内核信息排查
	echo -e "${YELLOW}正在检查内核信息[lsmod]:${NC}"  
	log_message "INFO" "正在检查内核信息"
	lsmod=$(lsmod 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "执行lsmod命令失败" "kernelCheck"
	fi
	if [ -n "$lsmod" ];then
		(echo "${YELLOW}[INFO] 内核信息如下:${NC}" && echo "$lsmod")  
		log_message "INFO" "内核信息获取成功"
	else
		echo "${YELLOW}[INFO] 未发现内核信息${NC}"  
		log_message "INFO" "未发现内核信息"
	fi
	printf "\n"  

	echo -e "${YELLOW}正在检查异常内核[lsmod|grep -Ev mod_list]:${NC}"  
	log_message "INFO" "正在检查异常内核模块"
	danger_lsmod=$(lsmod 2>/dev/null | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
	if [ $? -ne 0 ]; then
		handle_error 1 "执行lsmod命令检查异常内核模块失败" "kernelCheck"
	fi
	if [ -n "$danger_lsmod" ];then
		(echo -e "${RED}!]发现可疑内核模块:${NC}" && echo "$danger_lsmod")  
		log_message "INFO" "发现可疑内核模块"
	else
		echo -e "${GREEN}[SUCC] 未发现可疑内核模块${NC}"  
		log_message "INFO" "未发现可疑内核模块"
	fi
	printf "\n"  
	
	# 记录结束时间和性能统计
	end_time=$(date +%s)
	log_performance "kernelCheck" "$start_time" "$end_time"
	log_operation "MOUDLE - KERNELCHECK" "内核检查模块执行完成" "END"

}

# 系统文件完整性检查 【新增功能 - 来自LinuxCheck.sh】
system_file_integrity_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查系统文件完整性..."
	log_message "INFO" "正在检查系统文件完整性" "system_file_integrity_check"
	
	# 关键系统命令列表 (来自LinuxCheck.sh)
	local critical_commands=(
		"which"
		"ifconfig" 
		"ls"
		"login"
		"netstat"
		"top"
		"ps"
		"find"
		"grep"
		"passwd"
		"shadow"
		"curl"
		"wget"
	)
	
	echo -e "${YELLOW}[检查]${NC} 系统关键命令文件修改时间和大小"
	
	for cmd in "${critical_commands[@]}"; do
		# 使用which获取命令的实际路径
		local full_path=$(which "$cmd" 2>/dev/null)
		if [[ -n "$full_path" ]]; then
			# 如果命令存在，获取修改时间和文件大小
			if [[ -f "$full_path" ]]; then
				local mod_time=$(stat -c %y "$full_path" 2>/dev/null | cut -c1-19)
				local file_size=$(du -sh "$full_path" 2>/dev/null | cut -f1)
				echo -e "${GREEN}[INFO]${NC} 文件: $full_path | 修改时间: $mod_time | 大小: $file_size"
				log_message "INFO" "系统命令检查 - $full_path: 修改时间=$mod_time, 大小=$file_size" "system_file_integrity_check"
			else
				echo -e "${RED}[WARN]${NC} 命令路径异常: $full_path (不是常规文件)"
				log_message "WARN" "命令路径异常: $full_path" "system_file_integrity_check"
			fi
		else
			echo -e "${YELLOW}[NOTE]${NC} 命令 $cmd 不存在或未安装"
			log_message "INFO" "命令不存在: $cmd" "system_file_integrity_check"
		fi
	done
	
	# 检查文件类型信息
	if command -v file >/dev/null 2>&1; then
		echo -e "${YELLOW}[检查]${NC} 系统关键命令文件类型"
		for cmd in "${critical_commands[@]}"; do
			local full_path=$(which "$cmd" 2>/dev/null)
			if [[ -n "$full_path" && -f "$full_path" ]]; then
				local file_type=$(file -b "$full_path" 2>/dev/null)
				echo -e "${GREEN}[INFO]${NC} 文件: $full_path | 类型: $file_type"
				
				# 检查是否为可疑文件类型 (应该是ELF可执行文件)
				if [[ ! "$file_type" =~ ELF.*executable ]] && [[ ! "$file_type" =~ "shell script" ]] && [[ ! "$file_type" =~ "ASCII text" ]]; then
					echo -e "${RED}[WARN]${NC} 可疑文件类型: $full_path - $file_type"
					log_message "WARN" "可疑文件类型: $full_path - $file_type" "system_file_integrity_check"
				fi
			fi
		done
	else
		echo -e "${YELLOW}[NOTE]${NC} file命令不可用，跳过文件类型检查"
		log_message "INFO" "file命令不可用，跳过文件类型检查" "system_file_integrity_check"
	fi
	
	# 检查关键系统文件的修改时间
	echo -e "${YELLOW}[检查]${NC} 关键系统文件修改时间"
	local critical_files=(
		"/sbin/ifconfig"
		"/bin/ls"
		"/bin/login"
		"/bin/netstat"
		"/bin/top"
		"/bin/ps"
		"/bin/find"
		"/bin/grep"
		"/etc/passwd"
		"/etc/shadow"
		"/usr/bin/curl"
		"/usr/bin/wget"
		"/root/.ssh/authorized_keys"
	)
	
	for file_path in "${critical_files[@]}"; do
		if [[ -f "$file_path" ]]; then
			local mod_time=$(stat -c %y "$file_path" 2>/dev/null | cut -c1-19)
			echo -e "${GREEN}[INFO]${NC} 文件: $file_path | 修改时间: $mod_time"
			log_message "INFO" "关键文件检查 - $file_path: 修改时间=$mod_time" "system_file_integrity_check"
		else
			echo -e "${YELLOW}[NOTE]${NC} 文件不存在: $file_path"
		fi
	done
	
	echo -e "${GREEN}[SUCC]${NC} 系统文件完整性检查完成"
	printf "\n"
}

# 安全风险/漏洞检查 【新增功能 - 来自LinuxCheck.sh】
security_risk_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查安全风险和漏洞..."
	log_message "INFO" "正在检查安全风险和漏洞" "security_risk_check"
	
	# 1. Redis弱密码检测
	echo -e "${YELLOW}[检查]${NC} Redis弱密码检测"
	local redis_config="/etc/redis/redis.conf"
	if [[ -f "$redis_config" ]]; then
		local weak_passwords=$(grep -P '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)' "$redis_config" 2>/dev/null)
		if [[ -n "$weak_passwords" ]]; then
			echo -e "${RED}[WARN]${NC} 发现Redis弱密码:"
			echo "$weak_passwords" | while read -r line; do
				echo -e "  ${RED}→${NC} $line"
				log_message "WARN" "Redis弱密码: $line" "security_risk_check"
			done
		else
			echo -e "${GREEN}[SUCC]${NC} Redis密码配置安全"
		fi
	else
		echo -e "${YELLOW}[NOTE]${NC} Redis配置文件不存在: $redis_config"
	fi
	
	# 2. JDWP调试端口检测 (Java Debug Wire Protocol)
	echo -e "${YELLOW}[检查]${NC} JDWP调试端口检测"
	local jdwp_processes=$(ps aux | grep -P '(?:runjdwp|agentlib:jdwp)' | grep -v 'grep' 2>/dev/null)
	if [[ -n "$jdwp_processes" ]]; then
		echo -e "${RED}[WARN]${NC} 发现JDWP调试高风险进程:"
		echo "$jdwp_processes" | while read -r line; do
			echo -e "  ${RED}→${NC} $line"
			log_message "WARN" "JDWP调试进程: $line" "security_risk_check"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现JDWP调试进程"
	fi
	
	# 3. Python http.server 列目录检测
	echo -e "${YELLOW}[检查]${NC} Python http.server列目录检测"
	local http_server_processes=$(ps aux | grep -P 'http\.server' | grep -v 'grep' 2>/dev/null)
	if [[ -n "$http_server_processes" ]]; then
		echo -e "${RED}[WARN]${NC} 发现Python http.server进程(可能存在目录遍历风险):"
		echo "$http_server_processes" | while read -r line; do
			echo -e "  ${RED}→${NC} $line"
			log_message "WARN" "Python http.server进程: $line" "security_risk_check"
		done
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现Python http.server进程"
	fi
	
	# 4. 检查MySQL/MariaDB弱密码 (扩展功能)
	echo -e "${YELLOW}[检查]${NC} MySQL/MariaDB弱密码检测"
	local mysql_configs=("/etc/mysql/mysql.conf.d/mysqld.cnf" "/etc/my.cnf" "/etc/mysql/my.cnf")
	local mysql_weak_found=false
	for config in "${mysql_configs[@]}"; do
		if [[ -f "$config" ]]; then
			# 检查是否有密码配置
			local mysql_passwords=$(grep -i "password" "$config" 2>/dev/null | grep -v "^#")
			if [[ -n "$mysql_passwords" ]]; then
				echo -e "${YELLOW}[INFO]${NC} MySQL配置文件 $config 包含密码配置"
				# 检查弱密码模式
				local weak_mysql=$(echo "$mysql_passwords" | grep -P "(123456|admin|root|password|test|mysql)")
				if [[ -n "$weak_mysql" ]]; then
					echo -e "${RED}[WARN]${NC} 发现MySQL可能的弱密码配置: $config"
					log_message "WARN" "MySQL弱密码配置: $config" "security_risk_check"
					mysql_weak_found=true
				fi
			fi
		fi
	done
	if [[ "$mysql_weak_found" == false ]]; then
		echo -e "${GREEN}[SUCC]${NC} MySQL密码配置检查通过"
	fi
	
	# 5. 检查SSH弱配置 (扩展功能)
	echo -e "${YELLOW}[检查]${NC} SSH安全配置检测"
	local sshd_config="/etc/ssh/sshd_config"
	if [[ -f "$sshd_config" ]]; then
		# 检查空密码登录
		local permit_empty_passwords=$(grep -i "PermitEmptyPasswords" "$sshd_config" | grep -v "^#" | grep -i "yes")
		if [[ -n "$permit_empty_passwords" ]]; then
			echo -e "${RED}[WARN]${NC} SSH允许空密码登录: $permit_empty_passwords"
			log_message "WARN" "SSH允许空密码登录" "security_risk_check"
		fi
		
		# 检查root登录
		local permit_root_login=$(grep -i "PermitRootLogin" "$sshd_config" | grep -v "^#" | grep -i "yes")
		if [[ -n "$permit_root_login" ]]; then
			echo -e "${YELLOW}[INFO]${NC} SSH允许root登录: $permit_root_login"
		fi
		
		# 检查密码认证
		local password_auth=$(grep -i "PasswordAuthentication" "$sshd_config" | grep -v "^#" | grep -i "yes")
		if [[ -n "$password_auth" ]]; then
			echo -e "${YELLOW}[INFO]${NC} SSH启用密码认证: $password_auth"
		fi
	else
		echo -e "${YELLOW}[NOTE]${NC} SSH配置文件不存在: $sshd_config"
	fi
	
	# 6. 检查FTP服务风险 (扩展功能)
	echo -e "${YELLOW}[检查]${NC} FTP服务风险检测"
	local ftp_processes=$(ps aux | grep -E '(vsftpd|proftpd|pure-ftpd)' | grep -v 'grep' 2>/dev/null)
	if [[ -n "$ftp_processes" ]]; then
		echo -e "${YELLOW}[INFO]${NC} 发现FTP服务进程:"
		echo "$ftp_processes" | while read -r line; do
			echo -e "  ${YELLOW}→${NC} $line"
		done
		log_message "INFO" "发现FTP服务进程" "security_risk_check"
	else
		echo -e "${GREEN}[SUCC]${NC} 未发现FTP服务进程"
	fi
	
	echo -e "${GREEN}[SUCC]${NC} 安全风险/漏洞检查完成"
	printf "\n"
}

# 其他排查 【完成】
otherCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - OTHERCHECK" "其他检查模块" "START"
	
	# 【新增】系统文件完整性检查 (来自LinuxCheck.sh)
	system_file_integrity_check
	
	# 【新增】风险/漏洞检查 (来自LinuxCheck.sh)
	security_risk_check
	
	# 可疑脚本文件排查
	echo -e "${YELLOW}正在检查可疑脚本文件[py|sh|per|pl|exe]:${NC}"  
	log_message "INFO" "正在检查可疑脚本文件"
	echo -e "${YELLOW}[NOTE]不检查/usr,/etc,/var目录,需要检查请自行修改脚本,脚本需要人工判定是否有害${NC}"  
	log_message "INFO" "不检查/usr,/etc,/var目录,需要检查请自行修改脚本,脚本需要人工判定是否有害"
	scripts=$(find / *.* 2>/dev/null | egrep "\.(py|sh|per|pl|exe)$" | egrep -v "/usr|/etc|/var")
	if [ $? -ne 0 ]; then
		handle_error 1 "执行find命令搜索可疑脚本文件失败" "otherCheck"
	fi
	if [ -n "$scripts" ];then
		(echo -e "${RED}[WARN] 发现以下脚本文件,请注意!${NC}" && echo "$scripts")  
		log_message "INFO" "发现可疑脚本文件"
	else
		echo -e "${GREEN}[SUCC] 未发现可疑脚本文件${NC}"  
		log_message "INFO" "未发现可疑脚本文件"
	fi
	printf "\n"  


	# 系统文件完整性校验
	# 通过取出系统关键文件的MD5值,一方面可以直接将这些关键文件的MD5值通过威胁情报平台进行查询
	# 另一方面,使用该软件进行多次检查时会将相应的MD5值进行对比,若和上次不一样,则会进行提示
	# 用来验证文件是否被篡改
	echo -e "${YELLOW}[INFO] md5查询威胁情报或者用来防止二进制文件篡改(需要人工比对md5值)${NC}"  
	log_message "INFO" "开始系统文件完整性校验"
	echo -e "${YELLOW}[INFO] MD5值文件导出位置: ${check_file}/sysfile_md5.txt${NC}"  
	log_message "INFO" "MD5值文件导出位置: ${check_file}/sysfile_md5.txt"

	file="${check_file}/sysfile_md5.txt"

	# 要检查的目录列表
	dirs_to_check=(
		/bin
		/usr/bin
		/sbin
		/usr/sbin
		/usr/lib/systemd
		/usr/local/bin
	)

	if [ -e "$file" ]; then 
		log_message "INFO" "发现已存在的MD5文件,进行校验对比"
		md5sum -c "$file" 2>&1  
		if [ $? -ne 0 ]; then
			handle_error 1 "MD5校验对比失败" "otherCheck"
		fi
	else
		log_message "INFO" "未发现MD5文件,开始生成新的MD5文件"
		# 清空或创建文件
		> "$file"
		if [ $? -ne 0 ]; then
			handle_error 1 "创建MD5文件失败" "otherCheck"
		fi

		# 遍历每个目录,查找可执行文件
		for dir in "${dirs_to_check[@]}"; do
			if [ -d "$dir" ]; then
				echo -e "${YELLOW}[INFO] 正在扫描目录${NC}: $dir"  
				log_message "INFO" "正在扫描目录: $dir"

				# 查找当前目录下所有具有可执行权限的普通文件
			exec_files=$(find "$dir" -maxdepth 1 -type f -executable 2>/dev/null)
			if [ $? -ne 0 ]; then
				handle_error 1 "查找目录 $dir 中的可执行文件失败" "otherCheck"
			fi
			if [ -n "$exec_files" ]; then
				echo "$exec_files" | while read -r f; do
					# 输出文件名和MD5值(输出屏幕同时保存到文件中)
					md5sum "$f" 2>/dev/null | tee -a "$file"  
				done
			fi
			else
				echo -e "${RED}[WARN] 目录不存在${NC}: $dir"  
				log_message "INFO" "目录不存在: $dir"
			fi
		done
	fi

	# 安装软件排查(rpm)
	echo -e "${YELLOW}正在检查rpm安装软件及版本情况[rpm -qa]:${NC}"  
	log_message "INFO" "正在检查rpm安装软件及版本情况"
	software=$(rpm -qa 2>/dev/null | awk -F- '{print $1,$2}' | sort -nr -k2 | uniq)
	if [ $? -ne 0 ]; then
		handle_error 1 "执行rpm -qa命令失败" "otherCheck"
	fi
	if [ -n "$software" ];then
		(echo -e "${YELLOW}[INFO] 系统安装与版本如下:${NC}" && echo "$software")  
		log_message "INFO" "发现系统安装软件"
	else
		echo -e "${YELLOW}[INFO] 系统未安装软件${NC}" 
		log_message "INFO" "系统未安装软件"
	fi
	printf "\n"  

	echo -e "${YELLOW}正在检查rpm安装的可疑软件:${NC}" 
	log_message "INFO" "正在检查rpm安装的可疑软件"
	# 从文件中取出一个工具名然后匹配
	hacker_tools_list=$(cat ${current_dir}/checkrules/hackertoolslist.txt 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "读取黑客工具列表文件失败" "otherCheck"
	fi
	for hacker_tools in $hacker_tools_list;do
		danger_soft=$(rpm -qa 2>/dev/null | awk -F- '{print $1}' | sort | uniq | grep -E "$hacker_tools")
		if [ -n "$danger_soft" ];then
			(echo -e "${RED}[WARN] 发现安装以下可疑软件:$hacker_tools${NC}" && echo "$danger_soft") 
			log_message "INFO" "发现安装可疑软件: $hacker_tools"
		else
			echo -e "${GREEN}[SUCC] 未发现安装可疑软件:$hacker_tools${NC}" 
			log_message "INFO" "未发现安装可疑软件: $hacker_tools"
		fi
	done
	printf "\n" 
	
	# 记录结束时间和性能统计
	end_time=$(date +%s)
	log_performance "otherCheck" $start_time $end_time
	log_operation "MOUDLE - OTHERCHECK" "其他检查模块执行完成" "END"

}

# 防火墙信息检查函数 归档 -- baselineCheck】
firewallRulesCheck(){
    echo -e "${YELLOW}[INFO] 正在检查防火墙策略（允许/拒绝规则）:${NC}"

    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        echo -e "${YELLOW}[INFO] 检测到 firewalld 正在运行${NC}"
        
        # 获取所有启用的区域
        # ZONES=$(firewall-cmd --get-active-zones | awk '{print $1}')
        ZONES=$(firewall-cmd --get-active-zones | grep -v '^\s*$' | grep -v '^\s' | sort -u)

        for ZONE in $ZONES; do
            echo -e "${RED}[WARN] 区域 [${ZONE}] 的配置:${NC}"
            
            # 允许的服务
            SERVICES=$(firewall-cmd --zone=$ZONE --list-services 2>/dev/null)
            if [ -n "$SERVICES" ]; then
                echo -e "  [INFO] 允许的服务: $SERVICES"
            else
                echo -e "  [-] 没有配置允许的服务"
            fi

            # 允许的端口
            PORTS=$(firewall-cmd --zone=$ZONE --list-ports 2>/dev/null)
            if [ -n "$PORTS" ]; then
                echo -e "  [INFO] 允许的端口: $PORTS"
            else
                echo -e "  [-] 没有配置允许的端口"
            fi

            # 允许的源IP
            SOURCES=$(firewall-cmd --zone=$ZONE --list-sources 2>/dev/null)
            if [ -n "$SOURCES" ]; then
                echo -e "  [INFO] 允许的源IP: $SOURCES"
            else
                echo -e "  [-] 没有配置允许的源IP"
            fi

            # 拒绝的源IP（黑名单）
            DENY_IPS=$(firewall-cmd --zone=$ZONE --list-rich-rules | grep 'reject' | grep 'source address' | awk -F "'" '{print $2}')
            if [ -n "$DENY_IPS" ]; then
                echo -e "  [WARN] 拒绝的源IP: $DENY_IPS"
            else
                echo -e "  [-] 没有配置拒绝的源IP"
            fi

            printf "\n"
        done

    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}[INFO] 检测到 ufw 正在运行${NC}"
        ufw status numbered 2>/dev/null | sed 's/^/  /'

    elif command -v nft >/dev/null 2>&1; then
        # nftables: 显示 filter 表 input/output/forward 链的默认策略与规则概览
        if systemctl is-active --quiet nftables || nft list ruleset 2>/dev/null | grep -q "table "; then
            echo -e "${YELLOW}[INFO] 检测到 nftables 规则集${NC}"
            local policy_input=$(nft list ruleset 2>/dev/null | awk '/hook input/ {f=1} f && /policy/ {print; f=0}')
            local policy_output=$(nft list ruleset 2>/dev/null | awk '/hook output/ {f=1} f && /policy/ {print; f=0}')
            local policy_forward=$(nft list ruleset 2>/dev/null | awk '/hook forward/ {f=1} f && /policy/ {print; f=0}')
            [ -n "$policy_input" ] && echo -e "  [INFO] input $policy_input"
            [ -n "$policy_output" ] && echo -e "  [INFO] output $policy_output"
            [ -n "$policy_forward" ] && echo -e "  [INFO] forward $policy_forward"
            echo -e "  [INFO] 简要规则(前50行):"
            nft list ruleset 2>/dev/null | sed -n '1,50p' | sed 's/^/    /'
        else
            echo -e "${YELLOW}[INFO] 未检测到活动的 nftables 规则集${NC}"
        fi

    elif [ -x /sbin/iptables ] && iptables -L -n -v &>/dev/null; then
        echo -e "${YELLOW}[INFO] 检测到 iptables 正在运行${NC}"

        echo -e "${RED}[WARN] 允许的规则(ACCEPT):${NC}"
        iptables -L -n -v | grep ACCEPT
        echo -e "${RED}[WARN] 拒绝的规则(REJECT/DROP):${NC}"
        iptables -L -n -v | grep -E 'REJECT|DROP'

    else
        echo -e "${YELLOW}[INFO] 未检测到 active 的防火墙服务(firewalld/nftables/iptables/ufw)${NC}"
    fi

    printf "\n"
}

# selinux状态检查函数 【归档 -- baselineCheck】
selinuxStatusCheck(){
    echo -e "${YELLOW}正在检查 SELinux 安全策略:${NC}"

    # 检查是否存在 SELinux 相关命令
    if ! command -v getenforce &>/dev/null && [ ! -f /usr/sbin/getenforce ] && [ ! -f /sbin/getenforce ]; then
        echo -e "${YELLOW}[INFO] 未安装 SELinux 工具,跳过检查${NC}"
        printf "\n"
        return
    fi

    # 获取 SELinux 当前状态
    SELINUX_STATUS=$(getenforce 2>/dev/null)

    case "$SELINUX_STATUS" in
        Enforcing)
            echo -e "${RED}[WARN] SELinux 正在运行于 enforcing 模式(强制模式)${NC}"
            ;;
        Permissive)
            echo -e "${YELLOW}[~]SELinux 处于 permissive 模式(仅记录不阻止)${NC}"
            ;;
        Disabled)
            echo -e "${RED}[X]SELinux 已禁用(disabled)${NC}"
            printf "\n"
            return
            ;;
        *)
            echo -e "${YELLOW}[?]无法识别 SELinux 状态: $SELINUX_STATUS${NC}"
            printf "\n"
            return
            ;;
    esac

    # 获取 SELinux 策略类型
    SELINUX_POLICY=$(sestatus | grep "Policy from config file" | awk '{print $NF}')
    if [ -n "$SELINUX_POLICY" ]; then
        echo -e "  [INFO] 当前 SELinux 策略类型: ${GREEN}$SELINUX_POLICY${NC}"
    else
        echo -e "  [-]无法获取 SELinux 策略类型"
    fi

    # 获取 SELinux 配置文件中的默认模式
    CONFIG_MODE=$(grep ^SELINUX= /etc/selinux/config | cut -d= -f2)
    if [ -n "$CONFIG_MODE" ]; then
        echo -e "  [i]配置文件中设定的默认模式: ${GREEN}${CONFIG_MODE^^}${NC}"
    else
        echo -e "  [-]无法读取 SELinux 默认启动模式配置"
    fi

    printf "\n"
}

# 基线检查【未完成】
baselineCheck(){
	# 基线检查项
	## 1.账户审查 调用 userInfoCheck 函数
	### 1.1 账户登录信息排查 调用 userInfoCheck 函数  函数需要修改
	echo -e "${YELLOW}==========基线检查==========${NC}" 
	echo -e "${YELLOW}正在检查账户信息:${NC}"
	userInfoCheck
	printf "\n"

	### 1.2 密码策略配置
	echo -e "${YELLOW}正在检查密码策略:${NC}" 
	echo -e "${YELLOW}[INFO] 正在检查密码有效期策略[/etc/login.defs ]:${NC}" 
	(echo -e "${YELLOW}[INFO] 密码有效期策略如下:${NC}" && cat /etc/login.defs | grep -v "#" | grep PASS ) 
	printf "\n" 

	echo -e "${YELLOW}正在进行口令生存周期检查:${NC}"  
	passmax=$(cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}')
	if [ $passmax -le 90 -a $passmax -gt 0 ];then
		echo -e "${YELLOW}[INFO] 口令生存周期为${passmax}天,符合要求(要求:0<密码有效期<90天)${NC}"  
	else
		echo -e "${RED}[WARN] 口令生存周期为${passmax}天,不符合要求,建议设置为1-90天${NC}" 
	fi

	echo -e "${YELLOW}正在进行口令更改最小时间间隔检查:${NC}" 
	passmin=$(cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}')
	if [ $passmin -ge 6 ];then
		echo -e "${YELLOW}[INFO] 口令更改最小时间间隔为${passmin}天,符合要求(不小于6天)${NC}" 
	else
		echo -e "${RED}[WARN] 口令更改最小时间间隔为${passmin}天,不符合要求,建议设置不小于6天${NC}" 
	fi

	echo -e "${YELLOW}正在进行口令最小长度检查:${NC}" 
	passlen=$(cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}')
	if [ $passlen -ge 8 ];then
		echo -e "${YELLOW}[INFO] 口令最小长度为${passlen},符合要求(最小长度不小于8)${NC}" 
	else
		echo -e "${RED}[WARN] 口令最小长度为${passlen},不符合要求,建议设置最小长度大于等于8${NC}" 
	fi

	echo -e "${YELLOW}正在进行口令过期警告时间天数检查:${NC}" 
	passage=$(cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}')
	if [ $passage -ge 30 -a $passage -lt $passmax ];then
		echo -e "${YELLOW}[INFO] 口令过期警告时间天数为${passage},符合要求(要求大于等于30天并小于口令生存周期)${NC}" 
	else
		echo -e "${RED}[WARN] 口令过期警告时间天数为${passage},不符合要求,建议设置大于等于30并小于口令生存周期${NC}" 
	fi
	printf "\n" 

	echo -e "${YELLOW}正在检查密码复杂度策略[/etc/pam.d/system-auth]:${NC}" 
	(echo -e "[INFO] 密码复杂度策略如下:" && cat /etc/pam.d/system-auth | grep -v "#") | 
	printf "\n" 

	echo -e "${YELLOW}正在检查密码已过期用户[/etc/shadow]:${NC}" 
	NOW=$(date "+%s")
	day=$((${NOW}/86400))
	passwdexpired=$(grep -v ":[\!\*x]([\*\!])?:" /etc/shadow | awk -v today=${day} -F: '{ if (($5!="") && (today>$3+$5)) { print $1 }}')
	if [ -n "$passwdexpired" ];then
		(echo -e "${RED}[WARN] 以下用户的密码已过期:${NC}" && echo "$passwdexpired")  
	else
		echo -e "${GREEN}[SUCC] 未发现密码已过期用户${NC}" 
	fi
	printf "\n" 


	echo -e "${YELLOW}正在检查账号超时锁定策略[/etc/profile]:${NC}"  
	account_timeout=$(cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}')
	if [ "$account_timeout" != ""  ];then
		TMOUT=$(cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}')
		if [ $TMOUT -le 600 -a $TMOUT -ge 10 ];then
			echo -e "${YELLOW}[INFO] 账号超时时间为${TMOUT}秒,符合要求${NC}"  
		else
			echo -e "${RED}[WARN] 账号超时时间为${TMOUT}秒,不符合要求,建议设置小于600秒${NC}"  
	fi
	else
		echo -e "${RED}[WARN] 账号超时未锁定,不符合要求,建议设置小于600秒${NC}"  
	fi
	printf "\n"  


	#### 【这是一个通用的文件检查,centOS7 和 ubuntu 等系统都适用】
	# 角色: 这是 GRUB 2 引导加载程序的实际配置文件,包含了启动菜单项和其他引导信息。
	# 内容: 包含了所有可用操作系统条目、内核版本、启动参数等详细信息。这个文件通常非常复杂,并不适合直接手工编辑。
	# 生成方式: 此文件是由 grub2-mkconfig 命令根据 /etc/default/grub 文件中的设置以及其他脚本（如 /etc/grub.d/ 目录下的脚本）自动生成的。
	# 作用: 在系统启动时,GRUB 2 使用此文件来显示启动菜单并加载选定的操作系统或内核
	# /etc/grub2.cfg 是 /boot/grub2/grub.cfg 的软链接,如果要修改 grub 行为,应该修改 /etc/default/grub 文件,然后运行 grub2-mkconfig -o /boot/grub2/grub.cfg 来生成 /boot/grub2/grub.cfg 文件。
	echo -e "${YELLOW}[2.2.4]正在检查grub2密码策略[/boot/grub2/grub.cfg]:${NC}"
	echo -e "[INFO] grub2密码策略如下:"

	GRUB_CFG="/boot/grub2/grub.cfg"

	# 检查文件是否存在
	if [ ! -f "$GRUB_CFG" ]; then
		echo -e "${RED}[WARN] 文件 $GRUB_CFG 不存在,无法进行 grub2 密码策略检查${NC}"
	else
		# 检查是否配置了加密密码（推荐使用 password_pbkdf2）
		if grep -qE '^\s*password_pbkdf2' "$GRUB_CFG"; then
			echo -e "${GREEN}[SUCC] 已设置安全的grub2密码(PBKDF2加密),符合要求${NC}"
		else
			echo -e "${RED}[WARN] 未设置grub2密码,不符合安全要求!建议立即配置grub2密码保护${NC}"
		fi
	fi

	printf "\n"


	### 1.3 远程登录限制 
	#### 1.3.1 远程登录策略 TCP Wrappers
	# TCP Wrappers 是一种用于增强网络安全性的工具,它通过基于主机的访问控制来限制对网络服务的访问。
	# 一些流行的服务如 SSH (sshd)、FTP (vsftpd) 和 Telnet 默认支持 TCP Wrappers。
	# 尽管 TCP Wrappers 提供了一种简单的方法来控制对服务的访问,但随着更高级的防火墙和安全技术（例如 iptables、firewalld）的出现,TCP Wrappers 的使用已经不像过去那样普遍。
	# 然而,在某些环境中,它仍然是一个有效的补充措施。
	echo -e "${YELLOW}正在检查远程登录策略(基于 TCP Wrappers):${NC}"  
	echo -e "${YELLOW}正在检查远程允许策略[/etc/hosts.allow]:${NC}"  
	hostsallow=$(cat /etc/hosts.allow | grep -v '#')
	if [ -n "$hostsallow" ];then
		(echo -e "${RED}[WARN] 允许以下IP远程访问:${NC}" && echo "$hostsallow")  
	else
		echo -e "${GREEN}[SUCC] hosts.allow文件未发现允许远程访问地址${NC}"  
	fi
	printf "\n"   

	echo -e "${YELLOW}正在检查远程拒绝策略[/etc/hosts.deny]:${NC}"  
	hostsdeny=$(cat /etc/hosts.deny | grep -v '#')
	if [ -n "$hostsdeny" ];then
		(echo -e "${RED}[WARN] 拒绝以下IP远程访问:${NC}" && echo "$hostsdeny")  
	else
		echo -e "${GREEN}[SUCC] hosts.deny文件未发现拒绝远程访问地址${NC}"  
	fi
	printf "\n"   


	### 1.4 认证与授权
	#### 1.4.1 SSH安全增强 调用函数
	echo -e "[${YELLOW}正在检查SSHD配置策略:${NC}"  
	sshFileCheck
	printf "\n"
	
	#### 1.4.2 PAM策略


	#### 1.4.3 其他认证服务策略 


	## 2. 文件权限及访问控制 
	### 2.1 关键文件保护
	#### 2.1.1 文件权限策略(登录相关文件权限)
	echo -e "${YELLOW}正在检查登陆相关文件权限:${NC}"  
	# echo -e "${YELLOW}正在检查etc文件权限[etc]:${NC}"  
	
	# 检查文件权限函数 (目录不适用)
	check_file_perm(){
		local file_path=$1      # 文件路径
		local expected_perm=$2  # 期望的权限
		local desc=$3 			# 描述

		local RED='\033[0;31m'
		local BLUE='\033[0;34m'
		local YELLOW='\033[0;33m'
		local GREEN='\033[0;32m'
		local NC='\033[0m'

		if [ ! -f "$file_path" ]; then
			echo -e "${RED}[WARN] 文件 $file_path 不存在！${NC}"
			return
		fi

		local perm=$(stat -c "%A" "$file_path")
		if [ "$perm" == "$expected_perm" ]; then
			echo -e "${GREEN}[SUCC] $desc 权限正常 ($perm)${NC}"
		else
			echo -e "${RED}[WARN] $desc 权限异常 ($perm),建议改为 $expected_perm${NC}"
		fi
	}

	echo -e "${YELLOW}正在检查登陆相关文件权限${NC}"
	# check_file_perm "/etc" "drwxr-x---" "/etc (etc)" # /etc 是目录
	check_file_perm "/etc/passwd" "-rw-r--r--" "/etc/passwd (passwd)"
	# check_file_perm "/etc/shadow" "----------" "/etc/shadow (shadow)"
	check_file_perm "/etc/group" "-rw-r--r--" "/etc/group (group)"
	# check_file_perm "/etc/gshadow" "----------" "/etc/gshadow (gshadow)"
	check_file_perm "/etc/securetty" "-rw-------" "/etc/securetty (securetty)"
	check_file_perm "/etc/services" "-rw-r--r--" "/etc/services (services)"
	check_file_perm "/boot/grub2/grub.cfg" "-rw-------" "/boot/grub2/grub.cfg (grub.cfg)"
	check_file_perm "/etc/default/grub" "-rw-r--r--" "/etc/default/grub (grub)"
	check_file_perm "/etc/xinetd.conf" "-rw-------" "/etc/xinetd.conf"
	check_file_perm "/etc/security/limits.conf" "-rw-r--r--" "/etc/security/limits.conf (core dump config)"
	printf "\n"

	#### 2.1.2 文件属性安全检查
	echo -e "${YELLOW}正在检查关键文件属性安全[chattr]:${NC}"
	log_message "INFO" "开始检查文件属性安全"
	
	# 检查关键文件的chattr属性
	local critical_files=(
		"/etc/passwd"
		"/etc/shadow" 
		"/etc/group"
		"/etc/gshadow"
		"/etc/hosts"
		"/etc/fstab"
		"/etc/sudoers"
		"/root/.ssh/authorized_keys"
		"/home/*/.ssh/authorized_keys"
	)
	
	if command -v lsattr >/dev/null 2>&1; then
		for file_pattern in "${critical_files[@]}"; do
			# 处理通配符
			for file_path in $file_pattern; do
				if [[ -f "$file_path" ]]; then
					local attrs=$(lsattr "$file_path" 2>/dev/null | awk '{print $1}')
					if [[ -n "$attrs" ]]; then
						# 检查是否设置了不可变属性(i)或仅追加属性(a)
						if [[ "$attrs" == *"i"* ]]; then
							echo -e "${RED}[WARN]${NC} $file_path 设置了不可变属性(i): $attrs"
							log_message "WARN" "文件设置了不可变属性: $file_path ($attrs)"
						elif [[ "$attrs" == *"a"* ]]; then
							echo -e "${YELLOW}[INFO]${NC} $file_path 设置了仅追加属性(a): $attrs"
							log_message "INFO" "文件设置了仅追加属性: $file_path ($attrs)"
						else
							echo -e "${GREEN}[SUCC]${NC} $file_path 属性正常: $attrs"
						fi
					fi
				fi
			done
		done
	else
		echo -e "${YELLOW}[NOTE]${NC} lsattr命令不可用，跳过文件属性检查"
		log_message "INFO" "lsattr命令不可用，跳过文件属性检查"
	fi
	printf "\n"

	# core dump
	# Core Dump（核心转储） 是操作系统在程序异常崩溃（如段错误、非法指令等）时,自动生成的一个文件,记录了程序崩溃时的内存状态和进程信息
	echo -e "${YELLOW}正在检查 core dump 设置[/etc/security/limits.conf]${NC}"
	if (grep -qE '^\*\s+soft\s+core\s+0' /etc/security/limits.conf && grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf); then
		echo -e "${YELLOW}[INFO] core dump 已禁用,符合规范${NC}"
		# 虽然 core dump可以辅助排查系统崩溃,但是在生产和安全敏感场景中,core dump推荐禁用
	else
		echo -e "${RED}[WARN] core dump 未完全禁用,建议添加: * soft core 0 和 * hard core 0 到 limits.conf${NC}"
		# * 所有用户
		# soft 软限制,用户可自行调整上限
		# hard 硬限制,系统管理员可自行调整上限
		# core 0 表示禁止生成core文件
	fi



	#### 2.1.2 系统文件属性
		# 文件属性检查
		# 当一个文件或目录具有 "a" 属性时,只有特定的用户或具有超级用户权限的用户才能够修改、重命名或删除这个文件。
		# 其他普通用户在写入文件时只能进行数据的追加操作,而无法对现有数据进行修改或删除。
		# 属性 "i" 表示文件被设置为不可修改（immutable）的权限。这意味着文件不能被更改、重命名、删除或链接。
		# 具有 "i" 属性的文件对于任何用户或进程都是只读的,并且不能进行写入操作
	# check_file_attributes "/etc/shadow" "/etc/shadow 文件属性" "i"
	check_file_attributes(){
		local file="$1"            # 要检查的文件路径
		local desc="$2"            # 描述信息（可选）
		local required_attr="$3"   # 必须包含的属性,如 "i" 或 "a"（可选）

		local yellow='\033[1;33m'
		local red='\033[0;31m'
		local nc='\033[0m'

		echo -e "${yellow}[INFO] 正在检查文件属性: $desc (${file})${nc}"

		if [ ! -e "$file" ]; then
			echo -e "${red}[-] 文件 $file 不存在！${nc}"
			return 1
		fi

		# 检查是否支持 lsattr 命令
		if ! command -v lsattr &>/dev/null; then
			echo -e "${red}[-] 未安装 e2fsprogs,无法使用 lsattr 命令,请先安装相关工具包。${nc}"
			return 1
		fi

		# 获取文件属性字符串
		attr=$(lsattr "$file" 2>/dev/null | awk '{print $1}')

		flag=0

		# 检查是否设置 i 属性
		if [[ "$attr" == *i* ]]; then
			echo -e "${yellow}[INFO] 文件 $file 存在 'i' 安全属性（不可修改/删除）${nc}"
			flag=1
		fi

		# 检查是否设置 a 属性
		if [[ "$attr" == *a* ]]; then
			echo -e "${yellow}[INFO] 文件 $file 存在 'a' 安全属性（只允许追加）${nc}"
			flag=1
		fi

		# 如果没有设置任何安全属性
		if [ $flag -eq 0 ]; then
			echo -e "${red}[WARN] 文件 $file 不存在任何安全属性(推荐设置 'i' 或 'a')${nc}"
			echo -e "${red}    建议执行: chattr +i $file (完全保护)或 chattr +a $file (仅追加)${nc}"
			return 1
		else
			return 0
		fi
	}

	echo -e "${YELLOW}正在检查登陆相关文件属性:${NC}"  
	# 调用函数检测文件属性
	check_file_attributes "/etc/passwd" "/etc/passwd 文件属性" 
	check_file_attributes "/etc/shadow" "/etc/shadow 文件属性"
	check_file_attributes "/etc/group" "/etc/group 文件属性"
	check_file_attributes "/etc/gshadow" "/etc/gshadow 文件属性"



	echo -e "${YELLOW}正在检测useradd和userdel时间属性:${NC}"  
	echo -e "${GREEN}Access:访问时间,每次访问文件时都会更新这个时间,如使用more、cat${NC}"  
	echo -e "${GREEN}Modify:修改时间,文件内容改变会导致该时间更新${NC}"  
	echo -e "${GREEN}Change:改变时间,文件属性变化会导致该时间更新,当文件修改时也会导致该时间更新;但是改变文件的属性,如读写权限时只会导致该时间更新,不会导致修改时间更新${NC}"  
	echo -e "${YELLOW}正在检查useradd时间属性[/usr/sbin/useradd ]:${NC}"  
	echo -e "${YELLOW}[INFO] useradd时间属性:${NC}"  
	stat /usr/sbin/useradd | egrep "Access|Modify|Change" | grep -v '('  
	printf "\n"  

	echo -e "${YELLOW}正在检查userdel时间属性[/usr/sbin/userdel]:${NC}"  
	echo -e "${YELLOW}[INFO] userdel时间属性:${NC}"  
	stat /usr/sbin/userdel | egrep "Access|Modify|Change" | grep -v '('  
	printf "\n"  




	## 3. 网络配置与服务
	### 3.1 端口和服务审计


	### 3.2 防火墙配置
	#### 防火墙策略检查 firewalld 和 iptables  引用函数
	echo -e "${YELLOW}正在检查防火墙策略:${NC}"
    firewallRulesCheck
	printf "\n"  


	### 3.3 网络参数优化



	## 4. Selinux 策略
	echo -e "${YELLOW}正在检查selinux策略:${NC}"  
	# echo "selinux策略如下:" && grep -vE '#|^\s*$' /etc/sysconfig/selinux
	selinuxStatusCheck
	printf "\n"  

	## 5. 服务配置策略
	### 5.1 NIS(网络信息服务) 配置策略
	# NIS 它允许在网络上的多个系统之间共享一组通用的配置文件,比如密码文件（/etc/passwd）、组文件（/etc/group）和主机名解析文件（/etc/hosts）等
	# NIS 配置问价的一般格式: database: source1 [source2 ...],示例如下:
	# passwd: files nis
	# group: files nis
	# hosts: files dns
	echo -e "${YELLOW}正在检查NIS(网络信息服务)配置:${NC}"
	echo -e "${YELLOW}正在检查NIS配置文件[/etc/nsswitch.conf]:${NC}"  
	nisconfig=$(cat /etc/nsswitch.conf | egrep -v '#|^$')
	if [ -n "$nisconfig" ];then
		(echo -e "${YELLOW}[INFO] NIS服务配置如下:${NC}" && echo "$nisconfig")  
	else
		echo -e "${RED}[WARN] 未发现NIS服务配置${NC}"  
	fi
	printf "\n"  

	### 5.2 SNMP 服务配置
	# 这个服务不是默认安装的,没安装不存在默认配置文件
	echo -e "${YELLOW}正在检查SNMP(简单网络协议)配置策略:${NC}"  
	echo -e "${YELLOW}正在检查SNMP配置[/etc/snmp/snmpd.conf]:${NC}"  
	if [ -f /etc/snmp/snmpd.conf ];then
		public=$(cat /etc/snmp/snmpd.conf | grep public | grep -v ^# | awk '{print $4}')
		private=$(cat /etc/snmp/snmpd.conf | grep private | grep -v ^# | awk '{print $4}')
		if [ "$public" = "public" ];then
			echo -e "${YELLOW}发现snmp服务存在默认团体名public,不符合要求${NC}"  
			# Community String（团体字符串）:这是 SNMPv1 和 SNMPv2c 中用于身份验证的一个明文字符串。
			# 它类似于密码,用于限制谁可以访问设备的 SNMP 数据。默认情况下,许多设备设置为“public”,这是一个安全隐患,因此建议更改这个值
		fi
		if [ "$private" = "private" ];then
			echo -e "${YELLOW}发现snmp服务存在默认团体名private,不符合要求${NC}"  
		fi
	else
		echo -e "${YELLOW}snmp服务配置文件不存在,可能没有运行snmp服务(使用命令可检测是否安装:[rpm -qa | grep net-snmp])${NC}"  
	fi
	printf "\n"  

	### 5.3 Nginx配置策略
	# 只检查默认安装路径的 nginx 配置文件
	echo -e "${YELLOW}正在检查nginx配置策略:${NC}"  
	echo -e "${YELLOW}正在检查Nginx配置文件[nginx/conf/nginx.conf]:${NC}"  
	# nginx=$(whereis nginx | awk -F: '{print $2}')
	nginx_bin=$(which nginx) 
	if [ -n "$nginx_bin" ];then
		echo -e "${YELLOW}[INFO] 发现主机存在Nginx服务${NC}"  
		echo -e "${YELLOW}[INFO] Nginx服务二进制文件路径为:$nginx_bin${NC}"  
		# 获取 nginx 配置文件位置,如果 nginx -V 获取不到,则默认为/etc/nginx/nginx.conf
		config_output="$($nginx_bin -V 2>&1)"
		config_path=$(echo "$config_output" | awk '/configure arguments:/ {split($0,a,"--conf-path="); if (length(a[2])>0) print a[2]}')  # 获取 nginx 配置文件路径

		# 如果 awk 命令成功返回了配置文件路径,则使用它,否则使用默认路径
		if [ -n "$config_path" ] && [ -f "$config_path" ]; then
			ngin_conf="$config_path"
		else
			ngin_conf="/etc/nginx/nginx.conf"
		fi

		if [ -f "$ngin_conf" ];then
			(echo -e "${YELLOW}[INFO] Nginx配置文件可能的路径为:$ngin_conf ${NC}")    # 输出变量值
			echo -e "${YELLOW}[NOTE]这里只检测nginx.conf主配置文件,其他导入配置文件在主文件同级目录下,请人工排查${NC}"  
			(echo -e "${YELLOW}[INFO] Nginx配置文件内容为:${NC}" && cat $ngin_conf | grep -v "^$")     # 查看值文件内容
			echo -e "${YELLOW}[INFO] 正在检查Nginx端口转发配置[$ngin_conf]:${NC}"  
			nginxportconf=$(cat $ngin_conf | grep -E "listen|server|server_name|upstream|proxy_pass|location"| grep -v "^$")
			if [ -n "$nginxportconf" ];then
				(echo -e "${YELLOW}[INFO] 可能存在端口转发的情况,请人工分析:${NC}" && echo "$nginxportconf")  
			else
				echo -e "${GREEN}[SUCC] 未发现端口转发配置${NC}"  
			fi
		else
			echo -e "${RED}[WARN] 未发现Nginx配置文件${NC}"  
		fi
	else
		echo -e "${YELLOW}[INFO] 未发现Nginx服务${NC}"  
	fi
	printf "\n"  


	## 6. 日志记录与监控


	## 7. 备份和恢复策略


	## 8. 其他安全配置基准


}

# 检查 Kubernetes 集群基础信息
k8sClusterInfo() {
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - K8SCLUSTERINFO" "Kubernetes集群基础信息检查模块" "START"
	
	# 判断是否为 Kubernetes 环境（目录或命令存在）
    if ! { [ -d /etc/kubernetes ] || command -v kubectl &>/dev/null; }; then
        echo -e "${RED}[WARN] 未检测到 Kubernetes 环境,退出脚本${NC}"
        log_message "INFO" "未检测到 Kubernetes 环境,退出脚本"
        exit 0
    fi

    echo -e "${YELLOW}正在检查K8s集群基础信息:${NC}"
    log_message "INFO" "正在检查K8s集群基础信息"

	# 检查 Kubernetes 版本信息
    echo -e "\n${YELLOW}[INFO] 正在检查 Kubernetes 版本信息:${NC}"
    log_message "INFO" "正在检查 Kubernetes 版本信息"
	# kubectl 命令行工具,通过其向 API server 发送指令
    echo -e "${YELLOW}[INFO] kubectl 版本信息 (客户端/服务端):${NC}"
    if command -v kubectl &>/dev/null; then
        kubectl version 2>&1
        if [ $? -ne 0 ]; then
            handle_error 1 "获取kubectl版本信息失败" "k8sClusterInfo"
        fi
        log_message "INFO" "成功获取kubectl版本信息"
    else
        echo -e "${RED}[WARN] 警告: kubectl 命令未安装,无法获取版本信息${NC}"
        log_message "INFO" "kubectl 命令未安装,无法获取版本信息"
    fi

	# kubelet 运行在每个node上运行,用于管理容器的生命周期,检查kubelet服务状态
    echo -e "${YELLOW}[INFO] kubelet 版本信息:${NC}"
    if command -v kubelet &>/dev/null; then
        kubelet --version 2>&1
        if [ $? -ne 0 ]; then
            handle_error 1 "获取kubelet版本信息失败" "k8sClusterInfo"
        fi
        log_message "INFO" "成功获取kubelet版本信息"
    else
        echo -e "${RED}[WARN] 警告: kubelet 命令未安装,无法获取版本信息${NC}"
        log_message "INFO" "kubelet 命令未安装,无法获取版本信息"
    fi

    # 检查 Kubernetes 服务状态
    echo -e "${BLUE}1. 检查 Kubernetes 服务状态:${NC}"
    log_message "INFO" "检查 Kubernetes 服务状态"
    systemctl status kubelet 2>&1 | grep -v "No such process"
    if [ $? -ne 0 ]; then
        echo -e "${RED}kubelet 服务未运行${NC}"
        log_message "INFO" "kubelet 服务未运行"
    else
        log_message "INFO" "kubelet 服务状态检查完成"
    fi

    echo -e "\n${BLUE}2. 检查集群信息:${NC}"
    log_message "INFO" "检查集群信息"
    kubectl cluster-info 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取集群信息失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}3. 检查节点状态:${NC}"
    log_message "INFO" "检查节点状态"
    kubectl get nodes 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取节点状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}4. 检查所有命名空间中的 Pod 状态:${NC}"
    log_message "INFO" "检查所有命名空间中的 Pod 状态"
    kubectl get pods --all-namespaces 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取所有命名空间Pod状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}5. 检查系统 Pod 状态:${NC}"
    log_message "INFO" "检查系统 Pod 状态"
    kubectl get pods -n kube-system 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取系统Pod状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}6. 检查持久卷(PV)状态:${NC}"
    log_message "INFO" "检查持久卷(PV)状态"
    kubectl get pv 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取持久卷状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}7. 检查持久卷声明(PVC)状态:${NC}"
    log_message "INFO" "检查持久卷声明(PVC)状态"
    kubectl get pvc 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取持久卷声明状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}8. 检查服务状态:${NC}"
    log_message "INFO" "检查服务状态"
    kubectl get svc --all-namespaces 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取服务状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}9. 检查部署状态:${NC}"
    log_message "INFO" "检查部署状态"
    kubectl get deployments --all-namespaces 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取部署状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}10. 检查守护进程集状态:${NC}"
    log_message "INFO" "检查守护进程集状态"
    kubectl get daemonsets --all-namespaces 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取守护进程集状态失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}11. 检查事件信息:${NC}"
    log_message "INFO" "检查事件信息"
    kubectl get events --sort-by=.metadata.creationTimestamp 2>&1
    if [ $? -ne 0 ]; then
        handle_error 1 "获取事件信息失败" "k8sClusterInfo"
    fi

    echo -e "\n${BLUE}12. 检查 Kubernetes 配置文件:${NC}"
    log_message "INFO" "检查 Kubernetes 配置文件"

    # 定义要检查的 Kubernetes 配置文件路径
    K8S_CONFIG_FILES=(
        "/etc/kubernetes/kubelet.conf"
        "/etc/kubernetes/config"
        "/etc/kubernetes/apiserver"
        "/etc/kubernetes/controller-manager"
        "/etc/kubernetes/scheduler"
    )

    for config_file in "${K8S_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            echo -e "${BLUE}检查配置文件: $config_file${NC}"
            log_message "INFO" "检查配置文件: $config_file"

            # 检查文件权限
            echo -e "${YELLOW}[INFO] 文件权限:${NC}"
            ls -l "$config_file" 2>/dev/null
            if [ $? -ne 0 ]; then
                handle_error 1 "获取配置文件权限失败: $config_file" "k8sClusterInfo"
            fi

            # 检查常见安全配置项（示例：查看是否设置了认证和授权相关参数）
            echo -e "${YELLOW}[INFO] 关键配置项检查:${NC}"
            grep -E 'client-ca-file|token-auth-file|authorization-mode|secure-port' "$config_file" 2>&1
            if [ $? -ne 0 ]; then
                log_message "INFO" "配置文件 $config_file 中未发现关键配置项"
            fi

            # 如果是 kubelet.conf,额外检查是否有 insecure-port 设置为 0
            if [[ "$config_file" == "/etc/kubernetes/kubelet.conf" ]]; then
                echo -e "${YELLOW}[INFO] 检查 kubelet 是否禁用不安全端口:${NC}"
                if grep -q 'insecure-port=0' "$config_file"; then
                    echo -e "${GREEN}✓ 不安全端口已禁用${NC}"
                    log_message "INFO" "kubelet 不安全端口已禁用"
                else
                    echo -e "${RED}[WARN] 警告: kubelet 的不安全端口未禁用${NC}"
                    log_message "INFO" "kubelet 的不安全端口未禁用"
                fi
            fi

            echo -e ""
        else
            echo -e "${RED}[WARN] 配置文件 $config_file 不存在${NC}"
            log_message "INFO" "配置文件不存在: $config_file"
        fi
    done
    
    # 记录结束时间和性能统计
    end_time=$(date +%s)
    log_performance "k8sClusterInfo" $start_time $end_time
    log_operation "MOUDLE - K8SCLUSTERINFO" "Kubernetes集群基础信息检查模块执行完成" "END"
}

# 检查 Kubernetes Secrets 安全信息
k8sSecretCheck() {
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - K8SSECRETCHECK" "Kubernetes Secret检查模块" "START"
	
	# 判断是否为 Kubernetes 环境（目录或命令存在）
    if ! { [ -d /etc/kubernetes ] || command -v kubectl &>/dev/null; }; then
        echo -e "${RED}[WARN] 未检测到 Kubernetes 环境,退出脚本${NC}"
        log_message "INFO" "未检测到 Kubernetes 环境,退出脚本"
        exit 0
    fi

    echo -e "${YELLOW}正在检查K8s集群凭据(Secret)信息:${NC}"
    log_message "INFO" "正在检查K8s集群凭据(Secret)信息"

    # 创建 k8s 子目录用于存储 Secret 文件
    K8S_SECRET_DIR="${k8s_file}"  # 文件在 init_env 函数已经创建 k8s_file="${check_file}/k8s"
    if [ ! -d "$K8S_SECRET_DIR" ]; then
        mkdir -p "$K8S_SECRET_DIR"
        if [ $? -ne 0 ]; then
            handle_error 1 "创建K8S Secret目录失败" "k8sSecretCheck"
        fi
        echo -e "${YELLOW}[INFO] 重新创建目录: $K8S_SECRET_DIR${NC}"
        log_message "INFO" "重新创建目录: $K8S_SECRET_DIR"
    fi

    echo -e "\n${BLUE}1. 检查 Kubernetes Secrets:${NC}"
    log_message "INFO" "检查 Kubernetes Secrets"

    # 获取所有命名空间下的 Secret
    SECRETS=$(kubectl get secrets --all-namespaces 2>&1)
    if [ $? -ne 0 ]; then
        handle_error 1 "获取Kubernetes Secrets失败" "k8sSecretCheck"
    fi
    if echo "$SECRETS" | grep -q "No resources found"; then
        echo -e "${RED}[WARN] 未发现任何 Secret${NC}"
        log_message "INFO" "未发现任何 Secret"
    else
        echo -e "${YELLOW}[INFO] 发现以下 Secret:${NC}"
        log_message "INFO" "发现Kubernetes Secrets"
        echo "$SECRETS"

        # 列出每个 Secret 的详细信息及其关联的 Pod
        echo "$SECRETS" | awk 'NR>1 {print $1, $2}' | while read -r namespace secret_name; do
            echo -e "\n${BLUE}检查 Secret: $namespace/$secret_name${NC}"
            log_message "INFO" "检查 Secret: $namespace/$secret_name"

            # 显示 Secret 的详细信息
            kubectl describe secret "$secret_name" -n "$namespace" 2>&1
            if [ $? -ne 0 ]; then
                handle_error 1 "获取Secret详细信息失败: $namespace/$secret_name" "k8sSecretCheck"
            fi

            # 保存 Secret 原始数据到文件
            SECRET_YAML_FILE="${K8S_SECRET_DIR}/${namespace}_${secret_name}.yaml"
            kubectl get secret "$secret_name" -n "$namespace" -o yaml > "$SECRET_YAML_FILE" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${YELLOW}[INFO] 已保存 Secret 到文件: $SECRET_YAML_FILE${NC}"
                log_message "INFO" "已保存 Secret 到文件: $SECRET_YAML_FILE"
            else
                handle_error 1 "保存Secret到文件失败: $SECRET_YAML_FILE" "k8sSecretCheck"
            fi

            # 检查哪些 Pod 使用了该 Secret
            PODS_USING_SECRET=$(kubectl get pods -n "$namespace" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.volumes[?(@.secret.secretName=="'$secret_name'")].secret.secretName}{"\n"}{end}' 2>&1)
            if [ $? -ne 0 ]; then
                handle_error 1 "检查使用Secret的Pod失败: $namespace/$secret_name" "k8sSecretCheck"
            fi
            if [ -n "$PODS_USING_SECRET" ]; then
                echo -e "${YELLOW}[INFO] 使用此 Secret 的 Pod:${NC}"
                log_message "INFO" "发现使用Secret的Pod: $namespace/$secret_name"
                echo "$PODS_USING_SECRET" | grep -v '^$'
            else
                echo -e "${YELLOW}[INFO] 此 Secret 当前没有被任何 Pod 使用${NC}"
                log_message "INFO" "Secret未被任何Pod使用: $namespace/$secret_name"
            fi

            # 检查 Secret 数据内容（以 base64 解码为例）
            echo -e "${YELLOW}[INFO] Secret 数据内容 (Base64 解码):${NC}"
            SECRET_DATA=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.data}' 2>&1)
            if [ $? -ne 0 ]; then
                handle_error 1 "获取Secret数据内容失败: $namespace/$secret_name" "k8sSecretCheck"
            fi
            if [ -n "$SECRET_DATA" ]; then
                echo "$SECRET_DATA" | jq -r 'to_entries[] | "\(.key): \(.value | @base64d)"' 2>/dev/null
                log_message "INFO" "成功解码Secret数据内容: $namespace/$secret_name"
            else
                echo -e "${YELLOW}[INFO] 无数据或无法获取 Secret 内容${NC}"
                log_message "INFO" "无数据或无法获取Secret内容: $namespace/$secret_name"
            fi
        done
    fi
    
    # 记录结束时间和性能统计
    end_time=$(date +%s)
    log_performance "k8sSecretCheck" $start_time $end_time
    log_operation "MOUDLE - K8SSECRETCHECK" "Kubernetes Secret检查模块执行完成" "END"
}

# 收集 Kubernetes 敏感信息（仅查找指定目录下规定后缀的文件）
k8sSensitiveInfo() { 
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - K8SSENSITIVEINFO" "Kubernetes敏感信息收集模块" "START"
	
	# 判断是否为 Kubernetes 环境（目录或命令存在）
    if ! { [ -d /etc/kubernetes ] || command -v kubectl &>/dev/null; }; then
        echo -e "${RED}[WARN] 未检测到 Kubernetes 环境,退出脚本${NC}"
        log_message "INFO" "未检测到 Kubernetes 环境,退出脚本"
        exit 0
    fi

    echo -e "${YELLOW}正在收集K8s集群敏感信息(仅查找文件):${NC}"
    log_message "INFO" "正在收集K8s集群敏感信息"

    # 定义需要扫描的路径列表
    SCAN_PATHS=(
		"/var/lib/kubelet/pods/"
        "/var/run/secrets/kubernetes.io/serviceaccount/"
        "/etc/kubernetes/"
        "/root/.kube/"
        "/run/secrets/"
        "/var/lib/kubelet/config/"
        "/opt/kubernetes/"
        "/usr/local/etc/kubernetes/"
		# "/home/"
		# "/etc/"
		# "/var/lib/docker/"
		# "/usr/"
    )

    # 定义要查找的文件名模式（find -name 格式）
    search_patterns=(
        "*token*"
        "*cert*"
        "*credential*"
        "*.config"
		"*.conf"
        "*.kubeconfig*"
        ".kube/config"
		"ca.crt"
        "namespace"
		"*pass*.*"
		"*.key"
		"*secret"
		"*y*ml"
		"*c*f*g*.json"
    )

    # 创建输出目录用于保存发现的敏感文件
    K8S_SENSITIVE_DIR="${k8s_file}/k8s_sensitive"   # ${check_file}/k8s/k8s_sensitive
    if [ ! -d "$K8S_SENSITIVE_DIR" ]; then
        mkdir -p "$K8S_SENSITIVE_DIR"
        if [ $? -ne 0 ]; then
            handle_error 1 "创建K8S敏感信息目录失败" "k8sSensitiveInfo"
        fi
        echo -e "${YELLOW}[INFO] 创建目录: $K8S_SENSITIVE_DIR${NC}"
        log_message "INFO" "创建目录: $K8S_SENSITIVE_DIR"
    fi

    # 遍历每个路径
    for path in "${SCAN_PATHS[@]}"; do
        if [ -d "$path" ]; then
            echo -e "${YELLOW}[INFO] 正在扫描路径: $path${NC}"
            log_message "INFO" "正在扫描路径: $path"

            # 遍历每个文件模式
            for pattern in "${search_patterns[@]}"; do
                # 使用 find 匹配文件名模式,并安全处理带空格/换行的文件名
                find "$path" -type f -name "$pattern" -print0 2>/dev/null | while IFS= read -r -d '' file; do
                    if [ -f "$file" ]; then
                        echo -e "${RED}[WARN] 发现敏感文件: $file${NC}"
                        log_message "INFO" "发现敏感文件: $file"

						# 输出文件内容到终端
						# echo -e "${YELLOW}[INFO] 文件内容如下:${NC}"
						# cat "$file"

                        # 复制文件到输出目录
                        filename=$(basename "$file")
                        cp "$file" "$K8S_SENSITIVE_DIR/${filename}_$(date +%Y%m%d)" 2>/dev/null
                        if [ $? -eq 0 ]; then
                            echo -e "${YELLOW}[INFO] 已保存敏感文件副本至: $K8S_SENSITIVE_DIR/${filename}_$(date +%Y%m%d)${NC}"
                            log_message "INFO" "已保存敏感文件副本: ${filename}_$(date +%Y%m%d)"
                        else
                            handle_error 1 "保存敏感文件副本失败: $file" "k8sSensitiveInfo"
                        fi
                        echo -e ""
                    fi
                done
                # 检查find命令是否执行成功
                if [ $? -ne 0 ]; then
                    log_message "WARN" "扫描路径 $path 中的模式 $pattern 时出现错误"
                fi
            done
        else
            echo -e "${YELLOW}[INFO] 路径不存在或无权限访问: $path${NC}"
            log_message "INFO" "路径不存在或无权限访问: $path"
        fi
    done
    
    # 记录结束时间和性能统计
    end_time=$(date +%s)
    log_performance "k8sSensitiveInfo" $start_time $end_time
    log_operation "MOUDLE - K8SSENSITIVEINFO" "Kubernetes敏感信息收集模块执行完成" "END"
}

# Kubernetes 基线检查函数
k8sBaselineCheck() {
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - K8SBASELINECHECK" "Kubernetes基线检查模块" "START"
	
	# 判断是否为 Kubernetes 环境（目录或命令存在）
    if ! { [ -d /etc/kubernetes ] || command -v kubectl &>/dev/null; }; then
        echo -e "${RED}[WARN] 未检测到 Kubernetes 环境,退出脚本${NC}"
        log_message "INFO" "未检测到 Kubernetes 环境,退出脚本"
        exit 0
    fi

    echo -e "${YELLOW}正在执行 Kubernetes 基线安全检查:${NC}"
    log_message "INFO" "正在执行 Kubernetes 基线安全检查"

    echo -e "\n${BLUE}1. 控制平面配置检查:${NC}"
    log_message "INFO" "开始控制平面配置检查"
    # 检查 kubelet 配置是否存在 insecure-port=0
    if [ -f /etc/kubernetes/kubelet.conf ]; then
        echo -e "${YELLOW}[INFO] kubelet 是否禁用不安全端口:${NC}"
        log_message "INFO" "检查kubelet不安全端口配置"
        # 检查kubelet不安全端口配置
        if grep -q 'insecure-port=0' /etc/kubernetes/kubelet.conf 2>/dev/null; then
            echo -e "${GREEN}[SUCC] 不安全端口已禁用${NC}"
            log_message "INFO" "kubelet不安全端口已禁用"
        else
            # 检查grep命令是否因为文件读取错误而失败
            if [ ! -r "/etc/kubernetes/kubelet.conf" ]; then
                log_message "WARN" "无法读取kubelet配置文件: /etc/kubernetes/kubelet.conf"
            else
                echo -e "${RED}[WARN] 警告: kubelet 的不安全端口未禁用${NC}"
                log_message "INFO" "警告: kubelet的不安全端口未禁用"
            fi
        fi
    else
        echo -e "${YELLOW}[INFO] kubelet.conf 文件不存在,跳过检查${NC}"
        log_message "INFO" "kubelet.conf文件不存在,跳过检查"
    fi

    echo -e "\n${BLUE}2. RBAC 授权模式检查:${NC}"
    log_message "INFO" "开始RBAC授权模式检查"
    if [ -f /etc/kubernetes/apiserver ]; then
        echo -e "${YELLOW}[INFO] API Server 是否启用 RBAC:${NC}"
        log_message "INFO" "检查API Server RBAC配置"
        # 检查API Server RBAC配置
        if grep -q 'authorization-mode=.*RBAC' /etc/kubernetes/apiserver 2>/dev/null; then
            echo -e "${GREEN}✓ 已启用 RBAC 授权模式${NC}"
            log_message "INFO" "已启用RBAC授权模式"
        else
            # 检查grep命令是否因为文件读取错误而失败
            if [ ! -r "/etc/kubernetes/apiserver" ]; then
                log_message "WARN" "无法读取API Server配置文件: /etc/kubernetes/apiserver"
            else
                echo -e "${RED}[WARN] 警告: API Server 未启用 RBAC 授权模式${NC}"
                log_message "INFO" "警告: API Server未启用RBAC授权模式"
            fi
        fi
    else
        echo -e "${YELLOW}[INFO] apiserver 配置文件不存在,跳过检查${NC}"
        log_message "INFO" "apiserver配置文件不存在,跳过检查"
    fi

    echo -e "\n${BLUE}3. Pod 安全策略检查:${NC}"
    log_message "INFO" "开始Pod安全策略检查"
    echo -e "${YELLOW}[INFO] 是否启用 PodSecurityPolicy 或 Pod Security Admission:${NC}"
    log_message "INFO" "检查PodSecurityPolicy或Pod Security Admission"
    psp_enabled=$(kubectl api-resources 2>/dev/null | grep -E 'podsecuritypolicies|podsecurityadmission')
    if [ $? -ne 0 ]; then
        handle_error 1 "获取API资源信息失败" "k8sBaselineCheck"
    fi
    if [ -n "$psp_enabled" ]; then
        echo -e "${GREEN}✓ 已启用 Pod 安全策略${NC}"
        log_message "INFO" "已启用Pod安全策略"
    else
        echo -e "${RED}[WARN] 警告: 未检测到任何 Pod 安全策略机制${NC}"
        log_message "INFO" "警告: 未检测到任何Pod安全策略机制"
    fi

    echo -e "\n${BLUE}4. 网络策略(NetworkPolicy)检查:${NC}"
    log_message "INFO" "开始网络策略检查"
    netpolicy_enabled=$(kubectl api-resources 2>/dev/null | grep networkpolicies)
    if [ $? -ne 0 ]; then
        handle_error 1 "获取网络策略API资源信息失败" "k8sBaselineCheck"
    fi
    if [ -n "$netpolicy_enabled" ]; then
        echo -e "${GREEN}✓ 网络策略功能已启用${NC}"
        log_message "INFO" "网络策略功能已启用"
    else
        echo -e "${RED}[WARN] 警告: 未启用网络策略(NetworkPolicy),可能导致跨命名空间通信风险${NC}"
        log_message "INFO" "警告: 未启用网络策略,可能导致跨命名空间通信风险"
    fi

    echo -e "\n${BLUE}5. Secret 加密存储检查:${NC}"
    log_message "INFO" "开始Secret加密存储检查"
    echo -e "${YELLOW}[INFO] 是否启用 Secret 加密存储:${NC}"
    log_message "INFO" "检查Secret加密存储配置"
    encryption_config="/etc/kubernetes/encryption-config.yaml"
    if [ -f "$encryption_config" ]; then
        echo -e "${GREEN}✓ 已配置加密存储：$encryption_config${NC}"
        log_message "INFO" "已配置Secret加密存储: $encryption_config"
    else
        echo -e "${RED}[WARN] 警告: 未发现 Secret 加密配置文件${NC}"
        log_message "INFO" "警告: 未发现Secret加密配置文件"
    fi

    echo -e "\n${BLUE}6. 审计日志检查:${NC}"
    log_message "INFO" "开始审计日志检查"
    audit_log_path="/var/log/kube-audit/audit.log"
    if [ -f "$audit_log_path" ]; then
        echo -e "${GREEN}✓ 审计日志已启用,路径为: $audit_log_path${NC}"
        log_message "INFO" "审计日志已启用,路径: $audit_log_path"
    else
        echo -e "${RED}[WARN] 警告: 未发现审计日志文件${NC}"
        log_message "INFO" "警告: 未发现审计日志文件"
    fi

    echo -e "\n${BLUE}7. ServiceAccount 自动挂载 Token 检查:${NC}"
    log_message "INFO" "开始ServiceAccount自动挂载Token检查"
    default_sa=$(kubectl get serviceaccount default -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null)
    if [ $? -ne 0 ]; then
        handle_error 1 "获取默认ServiceAccount信息失败" "k8sBaselineCheck"
    fi
    if [ "$default_sa" = "false" ]; then
        echo -e "${GREEN}✓ 默认 ServiceAccount 未自动挂载 Token${NC}"
        log_message "INFO" "默认ServiceAccount未自动挂载Token"
    else
        echo -e "${RED}[WARN] 警告: 默认 ServiceAccount 启用了自动挂载 Token,存在提权风险${NC}"
        log_message "INFO" "警告: 默认ServiceAccount启用了自动挂载Token,存在提权风险"
    fi

    echo -e "\n${BLUE}8. Etcd 安全配置检查:${NC}"
    log_message "INFO" "开始Etcd安全配置检查"
    etcd_config="/etc/kubernetes/manifests/etcd.yaml"
    if [ -f "$etcd_config" ]; then
        echo -e "${YELLOW}[INFO] Etcd 是否启用 TLS 加密:${NC}"
        log_message "INFO" "检查Etcd TLS加密配置"
        # 检查Etcd TLS加密配置
        if grep -q '--cert-file' "$etcd_config" 2>/dev/null && grep -q '--key-file' "$etcd_config" 2>/dev/null; then
            echo -e "${GREEN}✓ Etcd 启用了 TLS 加密通信${NC}"
            log_message "INFO" "Etcd启用了TLS加密通信"
        else
            # 检查grep命令是否因为文件读取错误而失败
            if [ ! -r "$etcd_config" ]; then
                log_message "WARN" "无法读取Etcd配置文件: $etcd_config"
            else
                echo -e "${RED}[WARN] 警告: Etcd 未启用 TLS 加密通信${NC}"
                log_message "INFO" "警告: Etcd未启用TLS加密通信"
            fi
        fi

        echo -e "${YELLOW}[INFO] Etcd 是否限制客户端访问:${NC}"
        log_message "INFO" "检查Etcd客户端证书认证配置"
        # 检查Etcd客户端证书认证配置
        if grep -q '--client-cert-auth' "$etcd_config" 2>/dev/null; then
            echo -e "${GREEN}✓ Etcd 启用了客户端证书认证${NC}"
            log_message "INFO" "Etcd启用了客户端证书认证"
        else
            # 检查grep命令是否因为文件读取错误而失败
            if [ ! -r "$etcd_config" ]; then
                log_message "WARN" "无法读取Etcd配置文件进行客户端认证检查: $etcd_config"
            else
                echo -e "${RED}[WARN] 警告: Etcd 未启用客户端证书认证,可能存在未授权访问风险${NC}"
                log_message "INFO" "警告: Etcd未启用客户端证书认证,可能存在未授权访问风险"
            fi
        fi
    else
        echo -e "${YELLOW}[INFO] etcd.yaml 配置文件不存在,跳过检查${NC}"
        log_message "INFO" "etcd.yaml配置文件不存在,跳过检查"
    fi

    echo -e "\n${BLUE}9. 容器运行时安全配置:${NC}"
    log_message "INFO" "开始容器运行时安全配置检查"
    echo -e "${YELLOW}[INFO] 是否禁止以 root 用户运行容器:${NC}"
    log_message "INFO" "检查容器是否以root用户运行"
    pod_runasuser=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.securityContext.runAsUser}{"\n"}{end}' 2>/dev/null | sort -u)
    if [ $? -ne 0 ]; then
        handle_error 1 "获取Pod运行用户信息失败" "k8sBaselineCheck"
    fi
    if echo "$pod_runasuser" | grep -v '^$' | grep -q -v '0'; then
        echo -e "${GREEN}✓ 大多数 Pod 未以 root 用户运行${NC}"
        log_message "INFO" "大多数Pod未以root用户运行"
    else
        echo -e "${RED}[WARN] 警告: 存在以 root 用户运行的容器,请检查 Pod 安全上下文配置${NC}"
        log_message "INFO" "警告: 存在以root用户运行的容器,请检查Pod安全上下文配置"
    fi

    echo -e "\n${BLUE}10. 特权容器检查:${NC}"
    log_message "INFO" "开始特权容器检查"
	# 使用检查配置文件件中是否存在 privileged==true 的方式判断是否是特权容器
    privileged_pods=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[?(@.securityContext.privileged==true)]}{"\n"}{end}' 2>/dev/null)
    if [ $? -ne 0 ]; then
        handle_error 1 "获取特权容器信息失败" "k8sBaselineCheck"
    fi
    if [ -z "$privileged_pods" ]; then
        echo -e "${GREEN}✓ 未发现特权容器(privileged)${NC}"
        log_message "INFO" "未发现特权容器"
    else
        echo -e "${RED}[WARN] 警告: 检测到特权容器,建议禁用或限制特权容器运行${NC}"
        log_message "WARN" "警告: 检测到特权容器,建议禁用或限制特权容器运行"
    fi
    
    # 记录结束时间和性能统计
    end_time=$(date +%s)
    log_performance "k8sBaselineCheck" $start_time $end_time
    log_operation "MOUDLE - K8SBASELINECHECK" "Kubernetes基线检查模块执行完成" "END"
}

# k8s排查
k8sCheck() {
    echo -e "${YELLOW}正在检查K8s系统信息:${NC}"
    # 判断环境是否使用 k8s 集群
	if [ -d /etc/kubernetes ] || command -v kubectl &>/dev/null; then 
		echo -e "${YELLOW}[INFO] 检测到 Kubernetes 环境,开始执行相关检查...${NC}"
		
		# 调用函数
		## 1. 集群基础信息
		k8sClusterInfo
		## 2. 集群安全信息
		k8sSecretCheck
		## 3. 集群敏感信息(会拷贝敏感文件到路径)
		k8sSensitiveInfo
		## 4. 集群基线检查
		k8sBaselineCheck
	else
		echo -e "${RED}[WARN] 未检测到 Kubernetes 环境,跳过所有 Kubernetes 相关检查${NC}"

	fi
}


# 系统性能评估 【完成】
performanceCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MOUDLE - PERFORMANCECHECK" "系统性能评估模块" "START"
	
	# 系统性能评估
	## 磁盘使用情况
	echo -e "${YELLOW}正在检查磁盘使用情况:${NC}"  
	log_message "INFO" "正在检查磁盘使用情况"
	echo -e "${YELLOW}[INFO] 磁盘使用情况如下:${NC}" && df -h 2>/dev/null
	if [ $? -ne 0 ]; then
		handle_error 1 "获取磁盘使用情况失败" "performanceCheck"
	fi
	printf "\n"  

	echo -e "${YELLOW}正在检查磁盘使用是否过大[df -h]:${NC}"  
	log_message "INFO" "检查磁盘使用率是否超过70%"
	echo -e "${YELLOW}[INFO] 使用超过70%告警${NC}"  
	# 获取磁盘使用率信息
	df_output=$(df -h 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取磁盘信息失败" "performanceCheck"
	fi
	df=$(echo "$df_output" | awk 'NR!=1{print $1,$5}' | awk -F% '{print $1}' | awk '{if ($2>70) print $1,$2}')
	if [ -n "$df" ];then
		(echo -e "${RED}[WARN] 硬盘空间使用过高,请注意!${NC}" && echo "$df" )  
		log_message "INFO" "硬盘空间使用过高: $df"
	else
		echo -e "${YELLOW}[INFO] 硬盘空间足够${NC}" 
		log_message "INFO" "硬盘空间足够"
	fi
	printf "\n"  

	## CPU使用情况
	echo -e "${YELLOW}正在检查CPU用情况[cat /proc/cpuinfo]:${NC}" 
	log_message "INFO" "正在检查CPU硬件信息"
	(echo -e "${YELLOW}CPU硬件信息如下:${NC}" && cat /proc/cpuinfo 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取CPU硬件信息失败" "performanceCheck"
	fi

	## 内存使用情况
	echo -e "${YELLOW}正在分析内存情况:${NC}"  
	log_message "INFO" "正在分析内存使用情况"
	(echo -e "${YELLOW}[INFO] 内存信息如下[cat /proc/meminfo]:${NC}" && cat /proc/meminfo 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取内存详细信息失败" "performanceCheck"
	fi
	(echo -e "${YELLOW}[INFO] 内存使用情况如下[free -m]:${NC}" && free -m 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取内存使用情况失败" "performanceCheck"
	fi
	printf "\n"  

	## 系统运行及负载情况
	echo -e "${YELLOW}系统运行及负载情况:${NC}"  
	log_message "INFO" "正在检查系统运行时间及负载情况"
	echo -e "${YELLOW}正在检查系统运行时间及负载情况:${NC}"  
	(echo -e "${YELLOW}[INFO] 系统运行时间如下[uptime]:${NC}" && uptime 2>/dev/null)
	if [ $? -ne 0 ]; then
		handle_error 1 "获取系统运行时间及负载情况失败" "performanceCheck"
	fi
	printf "\n"  
	
	# 网络流量情况【没有第三方工具无法检测】
	# yum install nload -y
	# nload ens192 
	echo -e "${YELLOW}网络流量情况:${NC}"
	log_message "INFO" "网络流量监控需要第三方工具nload"
	echo -e "${YELLOW}需要借助第三放工具nload进行流量监控,请自行安装并运行${NC}"
	echo -e "${GREEN}安装命令: yum install nload -y${NC}"
	echo -e "${GREEN}检查命令: nload ens192${NC}"
	
	# 记录结束时间和性能统计
	end_time=$(date +%s)
	log_performance "performanceCheck" $start_time $end_time
	log_operation "MOUDLE - PERFORMANCECHECK" "系统性能评估模块执行完成" "END"
}


# 查找敏感配置文件函数（支持多模式定义）【攻击角度通用】
findSensitiveFiles() {
	# find "/home/" -type f \
	# ! -path "/root/.vscode-server/*" \
	# ! -path "/proc/*" \
	# \( -name '*Jenkinsfile*' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json'  \)
    echo -e "${YELLOW}正在全盘查找敏感配置文件:${NC}"

	# 定义扫描目录
    SCAN_PATHS=(
        "/var/run/secrets/"
        "/etc/kubernetes/"
        "/root/"
        "/home/"
        "/tmp/"
        "/opt/"
		"/etc/"
		"/var/lib/docker/"
		"/usr/"
    )

	# 定义排除目录
    EXCLUDE_DIRS=(
        "/root/.vscode-server/"
        "/proc/"
        "/dev/"
        "/run/"
        "/sys/"
        "*/node_modules/*"
		"*/site-packages/*"
		"*/.cache/*"
    )

	# 定义搜索模式(文件名)
    search_patterns=(
        '*Jenkinsfile*'
        'nacos'
        '*kubeconfig*'
        '.gitlab-ci.yml'
        'conf'
        'config'
        '*.yaml'
        '*.yml'
        '*.json'
        '*.kubeconfig'
        'id_rsa'
        'id_ed25519'
    )

    SENSITIVE_DIR="${check_file}/sensitive_files"
    if [ ! -d "$SENSITIVE_DIR" ]; then
        mkdir -p "$SENSITIVE_DIR"
        echo -e "${YELLOW}[INFO] 创建敏感文件输出目录: $SENSITIVE_DIR${NC}"
    fi

    for path in "${SCAN_PATHS[@]}"; do
        if [ -d "$path" ]; then
            echo -e "${YELLOW}[INFO] 正在扫描路径: $path${NC}"
            find_cmd=(find "$path" -type f)
            for exdir in "${EXCLUDE_DIRS[@]}"; do
                find_cmd+=( ! -path "$exdir*" )
            done
            find_cmd+=( \( )
            for idx in "${!search_patterns[@]}"; do
                find_cmd+=( -name "${search_patterns[$idx]}" )
                if [ $idx -lt $((${#search_patterns[@]}-1)) ]; then
                    find_cmd+=( -o )
                fi
            done
            find_cmd+=( \) )
            files=$("${find_cmd[@]}")
            while IFS= read -r file; do
                [ -z "$file" ] && continue
                echo -e "${RED}[WARN] 发现敏感文件: $file${NC}"
                # echo -e "${YELLOW}[INFO] 文件内容如下:${NC}"
                # cat "$file"
                filename=$(basename "$file")
                ts=$(date +%Y%m%d%H%M%S)
                cp "$file" "$SENSITIVE_DIR/${ts}_${filename}"
                echo -e "${YELLOW}[INFO] 已保存副本至: $SENSITIVE_DIR/${ts}_${filename}${NC}\n"
            done <<< "$files"
        else
            echo -e "${YELLOW}[INFO] 路径不存在或无权限访问: $path${NC}"
        fi
    done

}

# 攻击角度信息收集
attackAngleCheck(){
	# 攻击角度信息
	echo -e "${YELLOW}正在进行攻击角度信息采集:${NC}"
	# 调用函数 【查找敏感文件】
	findSensitiveFiles 
	echo -e "${YELLOW}攻击角度信息采集完成${NC}"
}

# 日志统一打包 【完成-暂时没有输出检测报告】
checkOutlogPack(){ 
	# 检查文件统一打包
	echo -e "${YELLOW}正在打包系统原始日志[/var/log]:${NC}"  
	tar -czvf ${log_file}/system_log.tar.gz /var/log/ -P >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "${YELLOW}[INFO] 日志打包成功${NC}"  
	else
		echo -e "${RED}[WARN] 日志打包失败,请工人导出系统原始日志${NC}"  
	fi
	printf "\n"  


	echo -e "${YELLOW}正在打包linuGun检查日志到/output/目录下:${NC}"  
	# zip -r /tmp/yinguard_${ipadd}_${date}.zip /tmp/yinguard_${ipadd}_${date}/*
	tar -zcvf ${current_dir}/output/yinguard_${ipadd}_${date}.tar.gz  ${current_dir}/output/yinguard_${ipadd}_${date}/* -P >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "${YELLOW}[INFO] 检查文件打包成功${NC}"  
	else
		echo -e "${RED}[WARN] 检查文件打包失败,请工人导出日志${NC}"  
	fi
	
}


# 发送检查文件到指定的服务器
sendFileRemote() {
	# 参数说明: sendFileRemote [server_ip] [server_port] [token] [file_path]
	# 上传方式 curl -k -X POST http://[ip]:[port]/upload -H "Authorization: Bearer [token]" -F "file=@example.txt"
	
	local start_time=$(date +%s)
	local server_ip="$1"
	local server_port="$2"
	local token="$3"
	local file_path="$4"	
	
	log_operation "文件远程发送" "开始发送检查文件到远程服务器" "开始"
	log_message "INFO" "发送参数: 服务器=${server_ip}:${server_port}, 文件=${file_path:-自动检测}"
	
	# 检查必需参数
	if [ -z "$server_ip" ] || [ -z "$server_port" ] || [ -z "$token" ]; then
		echo -e "${RED}[WARN] 错误: 必须指定服务器IP、端口和认证token${NC}"
		echo -e "${YELLOW}[INFO] 使用方法: sendFileRemote <server_ip> <server_port> <token> [file_path]${NC}"
		echo -e "${YELLOW}[INFO] 示例: sendFileRemote 192.168.1.100 8080 your_token${NC}"
		handle_error 1 "缺少必需参数: server_ip, server_port, token" "sendFileRemote"
		return 1
	fi
	
	# 验证token格式（基本检查：长度至少8位,包含字母数字）
	if [ ${#token} -lt 8 ]; then
		echo -e "${RED}[WARN] 错误: token长度至少需要8位字符${NC}"
		handle_error 1 "token长度不足: ${#token}位,需要至少8位" "sendFileRemote"
		return 1
	fi
	
	if ! echo "$token" | grep -q '^[a-zA-Z0-9_-]\+$'; then
		echo -e "${RED}[WARN] 错误: token只能包含字母、数字、下划线和连字符${NC}"
		handle_error 1 "token格式无效: 包含非法字符" "sendFileRemote"
		return 1
	fi
	
	log_message "INFO" "token验证通过: 长度=${#token}位"
	
	# 如果没有指定文件路径,自动查找生成的tar.gz文件
	if [ -z "$file_path" ]; then
		echo -e "${YELLOW}[INFO] 未指定文件路径,正在查找自动生成的检查文件...${NC}"
		
		# 构造预期的文件名
		local expected_file="${current_dir}/output/yinguard_${ipadd}_${date}.tar.gz"
		
		if [ -f "$expected_file" ]; then
			file_path="$expected_file"
			echo -e "${YELLOW}[INFO] 找到检查文件: $file_path${NC}"
		else
			echo -e "${RED}[WARN] 错误: 未找到自动生成的检查文件 $expected_file${NC}"
			echo -e "${YELLOW}[INFO] 请先运行 --all 完整检查或手动指定文件路径${NC}"
			return 1
		fi
	else
		# 将相对路径转换为绝对路径
		if [[ "$file_path" != /* ]]; then
			# 如果不是绝对路径（不以/开头）,则转换为绝对路径
			local original_path="$file_path"
			local converted_path=""
			
			if command -v realpath >/dev/null 2>&1; then
				# 优先使用realpath命令
				converted_path=$(realpath "$file_path" 2>/dev/null)
			fi
			
			# 如果realpath失败或不存在,尝试readlink
			if [ -z "$converted_path" ] && command -v readlink >/dev/null 2>&1; then
				# 备用readlink命令
				converted_path=$(readlink -f "$file_path" 2>/dev/null)
			fi
			
			# 如果以上方法都失败,手动构造绝对路径
			if [ -z "$converted_path" ]; then
				# 手动构造绝对路径,使用脚本启动时的目录而不是当前工作目录
				converted_path="${current_dir}/$file_path"
			fi
			
			# 更新file_path
			file_path="$converted_path"
			echo -e "${YELLOW}[INFO] 相对路径已转换为绝对路径: $original_path -> $file_path${NC}"
		fi
		
		# 检查指定的文件是否存在
		if [ ! -f "$file_path" ]; then
			echo -e "${RED}[WARN] 错误: 指定的文件不存在: $file_path${NC}"
			return 1
		fi
	fi
	
	# 获取文件大小用于显示
	local file_size=$(du -h "$file_path" | cut -f1)
	
	echo -e "${YELLOW}[INFO] 正在发送检查文件到服务器 http://${server_ip}:${server_port}/upload${NC}"
	echo -e "${YELLOW}[INFO] 文件路径: $file_path${NC}"
	echo -e "${YELLOW}[INFO] 文件大小: $file_size${NC}"
	echo -e "${YELLOW}[INFO] 使用认证token: ${token:0:4}****${NC}"  # 只显示前4位,保护token隐私
	
	# 构造上传URL
	local upload_url="http://${server_ip}:${server_port}/upload"  # 路径需要和服务器端(tools/uploadServer/uploadServer.py)一致
	
	# 使用curl上传文件,包含Authorization头部
	echo -e "${YELLOW}[INFO] 开始上传文件...${NC}"
	curl_result=$(curl -k -X POST "$upload_url" \
		-H "Authorization: Bearer $token" \
		-H "User-Agent: yinguard-Security-Tool/1.0" \
		-F "file=@$file_path" \
		--connect-timeout 30 \
		--max-time 300 \
		2>&1)
	curl_exit_code=$?
	
	if [ $curl_exit_code -eq 0 ]; then
		echo -e "${YELLOW}[INFO] 文件上传成功!${NC}"
		echo -e "${YELLOW}[INFO] 服务器响应: $curl_result${NC}"
		# 记录上传日志
		echo "$(date '+%Y-%m-%d %H:%M:%S') - 文件上传成功: $file_path -> $server_ip:$server_port" >> "${check_file}/upload.log" 2>/dev/null
		log_message "INFO" "文件上传成功: $file_path -> $server_ip:$server_port"
		log_operation "文件远程发送" "文件上传到远程服务器成功" "成功"
	else
		echo -e "${RED}[WARN] 文件上传失败! (退出码: $curl_exit_code)${NC}"
		echo -e "${RED}[WARN] 错误信息: $curl_result${NC}"
		echo -e "${YELLOW}[INFO] 请检查:${NC}"
		echo -e "${YELLOW}    1. 此服务需要提前开启远端文件接收服务,请确认远端文件接收服务已运行${NC}"
		echo -e "${YELLOW}    2. 文件接收服务器工具位置: tools/uploadServer/uploadServer.py ${NC}"
		echo -e "${YELLOW}    3. 文件接收服务器运行方式: python3 uploadServer.py <IP> <PORT> <Token>)${NC}"
		echo -e "${YELLOW}    4. 文件接收服务器是否正在运行并监听指定端口${NC}"
		echo -e "${YELLOW}    5. 认证token是否正确${NC}"
		echo -e "${YELLOW}    6. 网络连接是否正常${NC}"
		# 记录失败日志 【日志路径: output/yinguard_xxx_2025xxxx/upload.log】
		echo "$(date '+%Y-%m-%d %H:%M:%S') - 文件上传失败: $file_path -> $server_ip:$server_port (错误码: $curl_exit_code)" >> "${check_file}/upload.log" 2>/dev/null
		handle_error 1 "文件上传失败: 退出码=$curl_exit_code, 错误=$curl_result" "sendFileRemote"
		log_operation "文件远程发送" "文件上传到远程服务器失败" "失败"
		return 1
	fi
	
	# 记录性能日志
	local end_time=$(date +%s)
	log_performance "sendFileRemote" "$start_time" "$end_time"
}



#### 主函数入口 ####
main() {
	local main_start_time=$(date +%s)
	local script_version="1.0"
	
	# 检查是否提供了参数
    if [ $# -eq 0 ]; then
		# 没有参数时显示logo和使用说明
		echoBanner
        usage
        exit 1
    fi
	
	# 将标准输入的内容同时输出到终端和文件
	log2file() {
		local log_file_path="$1"
		tee -a "$log_file_path" 
	}
	# funcA | log2file "log.txt"
	# --all 输出的函数后面都带上这个输出

	# 初始化环境【含有一些定义变量,必须放在最开头调用】
	init_env
	# 确保 root 权限执行
	ensure_root
	
	# 记录主函数启动日志
	# log_operation "yinguard MAIN" "yinguard v${script_version} CHECKING" "START"
	log_message "INFO" "yinguard v${script_version} CHECKING"
	log_message "INFO" "OPTIONS: $*"
	log_message "INFO" "USER: $(whoami), UID: $(id -u)"

    local run_all=false		# 信号量: 是否运行所有模块
    local modules=()  		# 模块列表,参数选定的模块会追加到这个列表中
    local interactive_mode=false 	# 信号量: 是否启用交互模式

    # 检查--send参数是否与其他参数组合使用（不允许）【--send参数不能与其他检查参数组合使用】
    if [[ "$*" == *"--send"* ]] && [ $# -gt 1 ]; then
        # 检查是否有--send以外的其他参数
        local has_other_params=false 	# 标记变量
        for arg in "$@"; do
            if [[ "$arg" != "--send" ]] && [[ "$arg" =~ ^-- ]]; then
                has_other_params=true	# 设置标记变量为true
                break	# 跳出一层循环(如果找到一个--send以外的参数,则跳出循环)
            fi
        done
        
		# 检测信号量 has_other_params 的值
        if [ "$has_other_params" = true ]; then
            echo -e "${RED}[WARN] 错误: --send参数不能与其他检查参数组合使用${NC}"
            echo -e "${YELLOW}[INFO] --send必须单独使用,格式: ./yinguard.sh --send <ip> <port> <token> [file]${NC}"
            echo -e "${YELLOW}[INFO] 推荐用法: 先执行检查,再发送结果${NC}"
            echo -e "${YELLOW}[INFO] 示例1: ./yinguard.sh --all${NC}"
            echo -e "${YELLOW}[INFO] 示例2: ./yinguard.sh --send 192.168.1.100 8080 your_token${NC}"
            echo ""
            usage
            exit 1
        fi
    fi

    # 检查是否是发送文件命令 【单独检测第一个参数是否是 --send】
    if [ "$1" = "--send" ]; then
        if [ $# -lt 4 ]; then	# 后续参数是否小于 4 个
            echo -e "${RED}[WARN] --send 参数不足,需要指定服务器IP、端口和认证token${NC}"
            echo -e "${YELLOW}[INFO] 使用方法: --send <server_ip> <server_port> <token> [file_path]${NC}"
            echo -e "${YELLOW}[INFO] 示例: --send 192.168.1.100 8080 your_secret_token${NC}"
            exit 1
        fi
        server_ip="$2"
        server_port="$3"
        token="$4"
        file_path="$5"  # 可能为空【为空就默认检测生成的打包文件并发送】
        sendFileRemote "$server_ip" "$server_port" "$token" "$file_path"
        exit $?		# $? 表示返回上一条命令的退出状态码 sendFileRemote 函数返回值 1 表示失败,0 表示成功
    fi

    # 解析所有参数【每多一个参数多追加一个模块】
    for arg in "$@"; do
        # 参数和模块绑定  --system[参数] modules+=("system") 模块名 $module 执行函数
        case "$arg" in
            -h|--help)
                usage
                exit 0
                ;;
			--show)
				print_summary
				exit 0
				;;
			--system)
                modules+=("system")
                ;;
			--system-baseinfo)
				modules+=("system-baseinfo")
				;;
			--system-user)
				modules+=("system-user")
				;;
			--system-crontab)
				modules+=("system-crontab")
				;;
			--system-history)
				modules+=("system-history")
				;;
			--network)
				modules+=("network")
				;;
			--psinfo)
				modules+=("psinfo")
				;;
			--file)
				modules+=("file")
				;;
			--file-systemservice)
				modules+=("file-systemservice")
				;;
			--file-dir)
				modules+=("file-dir")
				;;
			--file-keyfiles)
				modules+=("file-keyfiles")
				;;
			--file-systemlog)
				modules+=("file-systemlog")
				;;
			--backdoor)
				modules+=("backdoor")
				;;
			--tunnel)
				modules+=("tunnel")
				;;
			--tunnel-ssh)
				modules+=("tunnel-ssh")
				;;
			--webshell)
				modules+=("webshell")
				;;
			--virus)
				modules+=("virus")
				;;
			--container-escape)
				modules+=("container-escape")
				;;
			--advanced-threat|--supply-chain|--mining-detection|--apt-analysis)
				echo -e "${YELLOW}[NOTE]${NC} 高级威胁检测功能已合并到 --virus 模块中"
				echo -e "${YELLOW}[NOTE]${NC} 请使用 --virus 参数执行增强型恶意软件检测"
				modules+=("virus")
				;;
			--memInfo)
				modules+=("memInfo")
				;;
			--hackerTools)
				modules+=("hackerTools")
				;;
			--kernel)
				modules+=("kernel")
				;;
			--other)
				modules+=("other")
				;;
			--k8s)
				modules+=("k8s")
				;;
			--k8s-cluster)
				modules+=("k8s-cluster")
				;;
			--k8s-secret)
				modules+=("k8s-secret")
				;;
			--k8s-fscan)
				modules+=("k8s-fscan")
				;;
			--k8s-baseline)
				modules+=("k8s-baseline")
				;;
			--performance)
				modules+=("performance")
				;;
			--baseline)
                modules+=("baseline")
                ;;
			--baseline-firewall)
				modules+=("baseline-firewall")
				;;
			--baseline-selinux)
				modules+=("baseline-selinux")
				;;	
			--attack-filescan)
				modules+=("attack-filescan")
				;;
            --inter)
                interactive_mode=true
                ;;
            --all)
                run_all=true		# 信号量: 是否运行所有模块	
                ;;
            --html-report)
                # HTML报告生成，需要特殊处理
                html_report_mode=true
                # 检查下一个参数是否是文件名（不以--开头）
                shift
                if [[ -n "$1" && ! "$1" =~ ^-- ]]; then
                    html_report_filename="$1"
                    shift
                else
                    # 如果没有指定文件名，使用默认的时间戳文件名
                    html_report_filename="security_report_$(date +%Y%m%d_%H%M%S).html"
                fi
                ;;
            --remote-scan)
                # 远程批量检测，需要特殊处理
                remote_scan_mode=true
                shift
                if [[ -n "$1" && ! "$1" =~ ^-- ]]; then
                    remote_hosts_file="$1"
                    shift
                    if [[ -n "$1" && ! "$1" =~ ^-- ]]; then
                        remote_config_file="$1"
                        shift
                        if [[ -n "$1" && ! "$1" =~ ^-- ]]; then
                            remote_parallel_num="$1"
                            shift
                        else
                            remote_parallel_num="5"  # 默认并发数
                        fi
                    else
                        echo -e "${RED}[ERRO]${NC} --remote-scan 需要指定配置文件"
                        echo -e "${YELLOW}[INFO]${NC} 使用方法: --remote-scan <hosts_file> <config_file> [parallel_num]"
                        exit 1
                    fi
                else
                    echo -e "${RED}[ERRO]${NC} --remote-scan 需要指定主机文件"
                    echo -e "${YELLOW}[INFO]${NC} 使用方法: --remote-scan <hosts_file> <config_file> [parallel_num]"
                    exit 1
                fi
                ;;
            --create-remote-config)
                shift
                config_filename="${1:-remote_scan.conf}"
                create_remote_config_template "$config_filename"
                exit 0
                ;;
            --create-hosts-template)
                shift
                hosts_filename="${1:-hosts.txt}"
                create_hosts_template "$hosts_filename"
                exit 0
                ;;
            *)
                echo -e "${RED}[WARN] 未知参数: $arg${NC}"
                usage
                exit 1
                ;;
        esac
    done

    # 定义所有一级模块【用于交互执行询问用户是否运行】每一个一级模块默认包含二级模块
    local all_modules=(system network psinfo file backdoor tunnel webshell virus container-escape memInfo hackerTools kernel other k8s performance baseline)

    # 如果指定了 --all,则运行所有模块【--all 不能和其他参数一起使用,且不包括--send】
    if [ "$run_all" = true ]; then
        modules=("${all_modules[@]}")  # 参数 --all 所有的一级模块加载进 modules 数组中（一级模块包含了二级模块）
    fi

    if [ ${#modules[@]} -gt 0 ]; then
        # 定义一个函数来获取模块对应的函数名（兼容Bash 3.2版本）
        get_module_function() {
            local module="$1"
            case "$module" in
                # 一级模块
                "system") echo "systemCheck" ;;
                "network") echo "networkInfo" ;;
                "psinfo") echo "processInfo" ;;
                "file") echo "fileCheck" ;;
                "backdoor") echo "backdoorCheck" ;;
                "tunnel") echo "tunnelCheck" ;;
                "webshell") echo "webshellCheck" ;;
                "virus") echo "virusCheck" ;;
                "container-escape") echo "containerEscapeCheck" ;;
                # 重构说明：高级威胁检测功能已合并到virus模块中
                # "advanced-threat"|"supply-chain"|"mining-detection"|"apt-analysis" 已废弃
                "memInfo") echo "memInfoCheck" ;;
                "hackerTools") echo "hackerToolsCheck" ;;
                "kernel") echo "kernelCheck" ;;
                "other") echo "otherCheck" ;;
                "k8s") echo "k8sCheck" ;;
                "performance") echo "performanceCheck" ;;
                "baseline") echo "baselineCheck" ;;
                
                # 二级模块 - 系统相关
                "system-baseinfo") echo "baseInfo" ;;
                "system-user") echo "userInfoCheck" ;;
                "system-crontab") echo "crontabCheck" ;;
                "system-history") echo "historyCheck" ;;
                
                # 二级模块 - 文件相关
                "file-systemservice") echo "systemServiceCheck" ;;
                "file-dir") echo "dirFileCheck" ;;
                "file-keyfiles") echo "specialFileCheck" ;;
                "file-systemlog") echo "systemLogCheck" ;;
                
                # 二级模块 - 隧道相关
                "tunnel-ssh") echo "tunnelSSH" ;;
                
                # 二级模块 - K8s相关
                "k8s-cluster") echo "k8sClusterInfo" ;;
                "k8s-secret") echo "k8sSecretCheck" ;;
                "k8s-fscan") echo "k8sSensitiveInfo" ;;
                "k8s-baseline") echo "k8sBaselineCheck" ;;
                
                # 二级模块 - 基线相关
                "baseline-firewall") echo "firewallCheck" ;;
                "baseline-selinux") echo "selinuxCheck" ;;
                
                # 二级模块 - 攻击相关
                "attack-filescan") echo "attackAngleCheck" ;;
                
                *) echo "" ;;  # 未知模块返回空字符串
            esac
        }
        
        # 验证模块映射关系
        for module in "${modules[@]}"; do
            func_name=$(get_module_function "$module")
            if [[ -z "$func_name" ]]; then
                echo "错误: 未知模块 $module"
                log_message "ERROR" "未知模块: $module"
                exit 1
            fi
        done
        
        if [ "$interactive_mode" = true ]; then  # 判断信号量是否进入交互模式【--inter 交互模式】
            log_message "INFO" "进入交互模式"
            for module in "${modules[@]}"; do
                read -p "是否执行模块 $module? (y/n): " choice
                # 转换为小写并去除空格
                choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
                if [[ ! "$choice" =~ ^(y|yes|n|no)$ ]]; then
                    echo "无效输入,跳过模块 $module"
                    log_message "WARN" "Invalid input for $module, skipping."
                    continue
                fi
                if [[ "$choice" == "y" || "$choice" == "yes" ]]; then
                    log_message "INFO" "用户选择执行模块: $module"
                    # 检查模块函数是否存在
                    func_name=$(get_module_function "$module")
                    if [[ -n "$func_name" ]]; then
                        log_message "INFO" "正在执行模块: $module (函数: $func_name)"
                        # 执行对应的模块函数并将输出重定向到结果文件
                        $func_name | log2file "${check_file}/checkresult.txt"
                        log_message "INFO" "模块 $module 执行完成"
                    else
                        echo "错误: 模块 $module 对应的函数未找到"
                        log_message "WARN" "模块 $module 对应的函数未找到,跳过执行"
                    fi
                else
                    echo "跳过模块 $module"
                    log_message "INFO" "用户选择跳过模块: $module"
                fi
            done
            # 日志打包函数
            sleep 2
            checkOutlogPack | log2file "${check_file}/checkresult.txt"
        else  # 非交互模式 - 自动执行所有指定的模块
            log_message "INFO" "进入非交互模式,自动执行所有模块"
            for module in "${modules[@]}"; do
                # 检查模块函数是否存在
                func_name=$(get_module_function "$module")
                 if [[ -n "$func_name" ]]; then
                     log_message "INFO" "正在执行模块: $module (函数: $func_name)"
                    # 执行对应的模块函数并将输出重定向到结果文件
                    $func_name | log2file "${check_file}/checkresult.txt"
                    log_message "INFO" "模块 $module 执行完成"
                else
                    log_message "WARN" "模块 $module 对应的函数未找到,跳过执行"
                fi
            done
            # 日志打包函数
            sleep 2
            checkOutlogPack | log2file "${check_file}/checkresult.txt"
        fi

        # 记录模块检查完成日志
        local main_end_time=$(date +%s)
        log_operation "模块检查" "指定模块检查完成: ${modules[*]}" "完成"
        log_performance "main" $main_start_time $main_end_time
    else
        echo -e "${RED}[WARN] 未指定任何有效的检查模块${NC}"
        log_message "ERROR" "未指定任何有效的检查模块"
        usage
        exit 1
    fi

    
    # 如果启用了远程批量检测模式
    if [ "$remote_scan_mode" = true ]; then
        echo -e "${BLUE}[INFO] 开始远程批量检测...${NC}"
        log_message "INFO" "开始远程批量检测: $remote_hosts_file" "main"
        
        # 执行远程批量检测
        remoteBatchScan "$remote_hosts_file" "$remote_config_file" "$remote_parallel_num"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[SUCC] 远程批量检测完成${NC}"
            log_message "INFO" "远程批量检测完成" "main"
        else
            echo -e "${RED}[ERRO] 远程批量检测失败${NC}"
            log_message "ERROR" "远程批量检测失败" "main"
        fi
        
        # 远程检测完成后直接退出，不执行其他检测
        local main_end_time=$(date +%s)
        local total_duration=$((main_end_time - main_start_time))
        echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] yinguard v${script_version} 远程批量检测完成,总耗时: ${total_duration}秒${NC}"
        log_operation "脚本执行" "yinguard v${script_version} 远程批量检测完成" "完成"
        log_message "INFO" "脚本总执行时间: ${total_duration}秒"
        exit 0
    fi
    
    # 如果启用了HTML报告生成模式
    if [ "$html_report_mode" = true ]; then
        echo -e "${BLUE}[INFO] 正在生成HTML报告...${NC}"
        log_message "INFO" "开始生成HTML报告: $html_report_filename"
        
        # 生成HTML报告
        generate_html_report "$html_report_filename"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[SUCC] HTML报告生成成功: ${check_file}/${html_report_filename}${NC}"
            log_message "INFO" "HTML报告生成成功: ${check_file}/${html_report_filename}"
        else
            echo -e "${RED}[ERRO] HTML报告生成失败${NC}"
            log_message "ERROR" "HTML报告生成失败"
        fi
    fi
    
    # 记录脚本执行完成
    local main_end_time=$(date +%s)
    local total_duration=$((main_end_time - main_start_time))
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] yinguard v${script_version} 执行完成,总耗时: ${total_duration}秒${NC}"
    log_operation "脚本执行" "yinguard v${script_version} 脚本执行完成" "完成"
    log_message "INFO" "脚本总执行时间: ${total_duration}秒"
}

# 容器逃逸检查 【新增功能】
containerEscapeCheck(){
	# 记录开始时间和模块开始日志
	start_time=$(date +%s)
	log_operation "MODULE - CONTAINER" "容器逃逸检查模块" "START"
	
	echo -e "${GREEN}[SUCC]${NC} 容器逃逸检查模块开始执行"
	echo ""
	
	# 执行各项容器安全检查
	container_environment_check
	container_capability_check
	container_mount_check
	container_process_check
	container_network_check
	
	# 记录结束时间和模块结束日志
	end_time=$(date +%s)
	execution_time=$((end_time - start_time))
	log_operation "MODULE - CONTAINER" "容器逃逸检查模块" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} 容器逃逸检查模块执行完成"
	printf "\n"
}

# 容器环境检测
container_environment_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查容器环境..."
	
	# 检查是否在容器中运行
	if [[ -f "/.dockerenv" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 检测到Docker容器环境 (/.dockerenv存在)"
		log_message "INFO" "检测到Docker容器环境" "containerEscapeCheck"
	fi
	
	# 检查cgroup信息
	if [[ -f "/proc/1/cgroup" ]]; then
		local cgroup_info=$(cat /proc/1/cgroup | grep -E "(docker|lxc|kubepods)")
		if [[ -n "$cgroup_info" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 检测到容器cgroup信息:"
			echo "$cgroup_info" | while read -r line; do
				echo -e "  ${YELLOW}→${NC} $line"
			done
		fi
	fi
	
	# 检查容器运行时
	echo -e "${BLUE}[INFO]${NC} 检查容器运行时状态..."
	if command -v docker >/dev/null 2>&1; then
		echo -e "${YELLOW}[NOTE]${NC} Docker运行状态:"
		local docker_ps=$(docker ps 2>/dev/null)
		if [[ $? -eq 0 && -n "$docker_ps" ]]; then
			echo "$docker_ps" | head -5
		else
			echo -e "  ${YELLOW}→${NC} 无法获取Docker容器信息或无运行中的容器"
		fi
	fi
	
	# 检查容器相关进程
	local container_processes=$(ps aux | grep -E "(dockerd|containerd|runc|docker-proxy)" | grep -v grep)
	if [[ -n "$container_processes" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 容器相关进程:"
		echo "$container_processes" | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	fi
}

# 容器权限检查
container_capability_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查容器权限配置..."
	
	# 检查CAP_SYS_ADMIN权限
	if command -v capsh >/dev/null 2>&1; then
		local cap_sys_admin=$(capsh --print | grep cap_sys_admin)
		if [[ -n "$cap_sys_admin" ]]; then
			echo -e "${RED}[WARN]${NC} 检测到CAP_SYS_ADMIN权限:"
			echo -e "  ${RED}→${NC} $cap_sys_admin"
			echo -e "  ${RED}→${NC} 此权限可能允许容器逃逸!"
			log_message "WARN" "检测到危险的CAP_SYS_ADMIN权限" "containerEscapeCheck"
		fi
		
		# 检查CAP_DAC_READ_SEARCH权限
		local cap_dac_read=$(capsh --print | grep cap_dac_read_search)
		if [[ -n "$cap_dac_read" ]]; then
			echo -e "${RED}[WARN]${NC} 检测到CAP_DAC_READ_SEARCH权限:"
			echo -e "  ${RED}→${NC} $cap_dac_read"
			echo -e "  ${RED}→${NC} 此权限可能允许绕过文件权限检查!"
			log_message "WARN" "检测到CAP_DAC_READ_SEARCH权限" "containerEscapeCheck"
		fi
		
		# 检查其他危险权限
		local dangerous_caps=(
			"cap_sys_ptrace" "cap_sys_module" "cap_dac_override"
			"cap_fowner" "cap_setuid" "cap_setgid"
		)
		
		for cap in "${dangerous_caps[@]}"; do
			local cap_result=$(capsh --print | grep "$cap")
			if [[ -n "$cap_result" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} 检测到权限: $cap"
				echo -e "  ${YELLOW}→${NC} $cap_result"
			fi
		done
	else
		echo -e "${YELLOW}[NOTE]${NC} 未找到capsh命令，无法检查容器权限"
	fi
}

# 容器挂载检查
container_mount_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查容器挂载配置..."
	
	# 检查危险的挂载点
	local dangerous_mounts=(
		"/proc" "/sys" "/dev" "/host" "/var/run/docker.sock"
		"/etc/passwd" "/etc/shadow" "/etc/hosts"
	)
	
	for mount_point in "${dangerous_mounts[@]}"; do
		if mount | grep -q "$mount_point"; then
			local mount_info=$(mount | grep "$mount_point")
			echo -e "${RED}[WARN]${NC} 检测到危险挂载: $mount_point"
			echo "$mount_info" | while read -r line; do
				echo -e "  ${RED}→${NC} $line"
			done
			log_message "WARN" "检测到危险挂载: $mount_point" "containerEscapeCheck"
		fi
	done
	
	# 检查Docker socket挂载
	if [[ -S "/var/run/docker.sock" ]]; then
		local socket_perms=$(ls -la /var/run/docker.sock)
		echo -e "${RED}[WARN]${NC} 检测到Docker socket:"
		echo -e "  ${RED}→${NC} $socket_perms"
		echo -e "  ${RED}→${NC} 此挂载可能允许容器逃逸!"
		log_message "WARN" "检测到Docker socket挂载" "containerEscapeCheck"
	fi
	
	# 检查特权模式标识
	if [[ -f "/proc/1/attr/current" ]]; then
		local selinux_context=$(cat /proc/1/attr/current 2>/dev/null)
		if [[ "$selinux_context" == *"unconfined"* ]]; then
			echo -e "${RED}[WARN]${NC} 检测到unconfined SELinux上下文:"
			echo -e "  ${RED}→${NC} $selinux_context"
			echo -e "  ${RED}→${NC} 可能运行在特权模式!"
			log_message "WARN" "检测到特权模式运行" "containerEscapeCheck"
		fi
	fi
}

# 容器进程检查
container_process_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查容器进程安全..."
	
	# 检查特权进程
	local privileged_procs=$(ps -eo pid,user,cmd | grep -E "(^root|sudo)" | grep -v grep)
	if [[ -n "$privileged_procs" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 检测到特权进程:"
		echo "$privileged_procs" | head -10 | while read -r proc; do
			echo -e "  ${YELLOW}→${NC} $proc"
		done
	fi
	
	# 检查容器逃逸相关进程
	local escape_processes=(
		"nsenter" "unshare" "chroot" "mount" "umount"
		"modprobe" "insmod" "rmmod"
	)
	
	for proc_name in "${escape_processes[@]}"; do
		local running_proc=$(ps aux | grep "$proc_name" | grep -v grep)
		if [[ -n "$running_proc" ]]; then
			echo -e "${RED}[WARN]${NC} 检测到潜在逃逸进程: $proc_name"
			echo "$running_proc" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
			done
			log_message "WARN" "检测到潜在逃逸进程: $proc_name" "containerEscapeCheck"
		fi
	done
}

# 容器网络检查
container_network_check() {
	echo -e "${BLUE}[INFO]${NC} 正在检查容器网络配置..."
	
	# 检查网络模式
	if ip link show | grep -q "docker0"; then
		echo -e "${YELLOW}[NOTE]${NC} 检测到Docker网桥:"
		ip link show docker0 2>/dev/null | while read -r line; do
			echo -e "  ${YELLOW}→${NC} $line"
		done
	fi
	
	# 检查容器网络接口
	local container_interfaces=$(ip link show | grep -E "veth|docker|br-")
	if [[ -n "$container_interfaces" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 检测到容器网络接口:"
		echo "$container_interfaces" | while read -r interface; do
			echo -e "  ${YELLOW}→${NC} $interface"
		done
	fi
	
	# 检查主机网络模式
	local host_network=$(ip route | grep -E "172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|10\.")
	if [[ -n "$host_network" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 网络路由信息:"
		echo "$host_network" | head -5 | while read -r route; do
			echo -e "  ${YELLOW}→${NC} $route"
		done
	fi
	
	# 检查端口转发
	local port_forwards=$(iptables -t nat -L 2>/dev/null | grep -E "DOCKER|REDIRECT")
	if [[ -n "$port_forwards" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 检测到Docker端口转发规则:"
		echo "$port_forwards" | head -5 | while read -r rule; do
			echo -e "  ${YELLOW}→${NC} $rule"
		done
	fi
}

# ========================================
# 远程批量检测框架 【第二阶段新功能】
# ========================================

# 远程批量检测主函数
remoteBatchScan() {
	local hosts_file="$1"
	local config_file="$2"
	local parallel_num="${3:-5}"  # 默认并发数为5
	
	# 记录开始时间
	local start_time=$(date +%s)
	log_operation "REMOTE - BATCH" "远程批量检测开始" "START"
	
	echo -e "${GREEN}[SUCC]${NC} 远程批量检测框架启动"
	echo -e "${BLUE}[INFO]${NC} 主机文件: $hosts_file"
	echo -e "${BLUE}[INFO]${NC} 配置文件: $config_file"
	echo -e "${BLUE}[INFO]${NC} 并发数量: $parallel_num"
	echo ""
	
	# 验证输入参数
	if ! remote_validate_params "$hosts_file" "$config_file"; then
		return 1
	fi
	
	# 创建远程检测结果目录
	local remote_results_dir="${check_file}/remote_scan_$(date +%Y%m%d_%H%M%S)"
	mkdir -p "$remote_results_dir"
	log_message "INFO" "创建远程检测结果目录: $remote_results_dir" "remoteBatchScan"
	
	# 读取配置文件
	remote_load_config "$config_file"
	
	# 执行批量扫描
	remote_execute_batch_scan "$hosts_file" "$remote_results_dir" "$parallel_num"
	
	# 生成汇总报告
	remote_generate_summary_report "$remote_results_dir"
	
	# 记录结束时间
	local end_time=$(date +%s)
	local execution_time=$((end_time - start_time))
	log_operation "REMOTE - BATCH" "远程批量检测完成" "END" "$execution_time"
	
	echo -e "${GREEN}[SUCC]${NC} 远程批量检测完成，结果保存在: $remote_results_dir"
	printf "\n"
}

# 验证远程检测参数
remote_validate_params() {
	local hosts_file="$1"
	local config_file="$2"
	
	# 检查主机文件
	if [[ ! -f "$hosts_file" ]]; then
		echo -e "${RED}[ERRO]${NC} 主机文件不存在: $hosts_file"
		log_message "ERROR" "主机文件不存在: $hosts_file" "remoteBatchScan"
		return 1
	fi
	
	# 检查配置文件
	if [[ ! -f "$config_file" ]]; then
		echo -e "${RED}[ERRO]${NC} 配置文件不存在: $config_file"
		log_message "ERROR" "配置文件不存在: $config_file" "remoteBatchScan"
		return 1
	fi
	
	# 检查SSH命令是否可用
	if ! command -v ssh >/dev/null 2>&1; then
		echo -e "${RED}[ERRO]${NC} SSH命令不可用，无法执行远程检测"
		log_message "ERROR" "SSH命令不可用" "remoteBatchScan"
		return 1
	fi
	
	# 检查并发处理工具
	if ! command -v xargs >/dev/null 2>&1; then
		echo -e "${RED}[ERRO]${NC} xargs命令不可用，无法执行并发处理"
		log_message "ERROR" "xargs命令不可用" "remoteBatchScan"
		return 1
	fi
	
	return 0
}

# 加载远程检测配置
remote_load_config() {
	local config_file="$1"
	
	echo -e "${BLUE}[INFO]${NC} 正在加载配置文件..."
	
	# 设置默认配置
	REMOTE_SSH_PORT="22"
	REMOTE_SSH_USER="root"
	REMOTE_SSH_TIMEOUT="30"
	REMOTE_SSH_OPTIONS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
	REMOTE_MODULES="system,network,psinfo"  # 默认检测模块
	REMOTE_SSH_KEY=""
	REMOTE_SSH_PASS=""
	
	# 读取配置文件
	if [[ -f "$config_file" ]]; then
		while IFS='=' read -r key value; do
			# 跳过注释和空行
			[[ "$key" =~ ^[[:space:]]*# ]] && continue
			[[ -z "$key" ]] && continue
			
			# 去除前后空格
			key=$(echo "$key" | xargs)
			value=$(echo "$value" | xargs)
			
			case "$key" in
				"SSH_PORT") REMOTE_SSH_PORT="$value" ;;
				"SSH_USER") REMOTE_SSH_USER="$value" ;;
				"SSH_TIMEOUT") REMOTE_SSH_TIMEOUT="$value" ;;
				"SSH_KEY") REMOTE_SSH_KEY="$value" ;;
				"SSH_PASS") REMOTE_SSH_PASS="$value" ;;
				"MODULES") REMOTE_MODULES="$value" ;;
				"SSH_OPTIONS") REMOTE_SSH_OPTIONS="$value" ;;
			esac
		done < "$config_file"
	fi
	
	echo -e "${YELLOW}[NOTE]${NC} 远程检测配置:"
	echo -e "  ${YELLOW}→${NC} SSH端口: $REMOTE_SSH_PORT"
	echo -e "  ${YELLOW}→${NC} SSH用户: $REMOTE_SSH_USER"
	echo -e "  ${YELLOW}→${NC} 连接超时: ${REMOTE_SSH_TIMEOUT}秒"
	echo -e "  ${YELLOW}→${NC} 检测模块: $REMOTE_MODULES"
	[[ -n "$REMOTE_SSH_KEY" ]] && echo -e "  ${YELLOW}→${NC} SSH密钥: $REMOTE_SSH_KEY"
	
	log_message "INFO" "远程检测配置加载完成" "remoteBatchScan"
}

# 执行批量扫描
remote_execute_batch_scan() {
	local hosts_file="$1"
	local results_dir="$2"
	local parallel_num="$3"
	
	echo -e "${BLUE}[INFO]${NC} 开始执行批量远程检测..."
	
	# 创建临时脚本文件用于并发执行
	local temp_script=$(mktemp)
	cat > "$temp_script" << 'EOF'
#!/bin/bash
remote_scan_single_host() {
	local host="$1"
	local results_dir="$2"
	
	# 解析主机信息 (支持格式: IP 或 IP:PORT 或 USER@IP:PORT)
	local ssh_host="$host"
	local ssh_port="$REMOTE_SSH_PORT"
	local ssh_user="$REMOTE_SSH_USER"
	
	if [[ "$host" == *"@"* ]]; then
		ssh_user="${host%%@*}"
		ssh_host="${host#*@}"
	fi
	
	if [[ "$ssh_host" == *":"* ]]; then
		ssh_port="${ssh_host##*:}"
		ssh_host="${ssh_host%:*}"
	fi
	
	local host_result_file="$results_dir/${ssh_host}_$(date +%H%M%S).log"
	local host_error_file="$results_dir/${ssh_host}_$(date +%H%M%S).err"
	
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始检测主机: $ssh_host" >> "$host_result_file"
	
	# 构建SSH连接命令
	local ssh_cmd="ssh $REMOTE_SSH_OPTIONS -p $ssh_port"
	[[ -n "$REMOTE_SSH_KEY" ]] && ssh_cmd="$ssh_cmd -i $REMOTE_SSH_KEY"
	
	# 测试连接
	if ! timeout "$REMOTE_SSH_TIMEOUT" $ssh_cmd "$ssh_user@$ssh_host" "echo 'Connection test successful'" >> "$host_result_file" 2>> "$host_error_file"; then
		echo "[ERROR] 无法连接到主机: $ssh_host" >> "$host_result_file"
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] 主机连接失败: $ssh_host" >> "$host_error_file"
		return 1
	fi
	
	# 上传并执行检测脚本
	local remote_script="/tmp/yinguard_remote_$(date +%s).sh"
	
	# 生成远程执行的检测命令
	local remote_commands=""
	IFS=',' read -ra modules <<< "$REMOTE_MODULES"
	for module in "${modules[@]}"; do
		case "$module" in
			"system")
				remote_commands="$remote_commands
echo '=== 系统基础信息 ==='
hostname; whoami; id; uname -a
echo '=== 系统版本信息 ==='
cat /etc/*release 2>/dev/null | head -10
echo '=== 系统时间和运行时间 ==='
date; uptime
echo '=== 磁盘使用情况 ==='
df -h
echo '=== 内存使用情况 ==='
free -h
"
				;;
			"network")
				remote_commands="$remote_commands
echo '=== 网络连接信息 ==='
netstat -antp 2>/dev/null | head -20
echo '=== 网络接口信息 ==='
ip addr 2>/dev/null || ifconfig 2>/dev/null
echo '=== 路由信息 ==='
ip route 2>/dev/null || route -n 2>/dev/null
"
				;;
			"psinfo")
				remote_commands="$remote_commands
echo '=== 进程信息 ==='
ps aux | head -20
echo '=== 高CPU进程 ==='
ps aux --sort=-%cpu | head -10
echo '=== 高内存进程 ==='
ps aux --sort=-%mem | head -10
"
				;;
			"security")
				remote_commands="$remote_commands
echo '=== 登录用户信息 ==='
who; w; last | head -10
echo '=== 定时任务 ==='
crontab -l 2>/dev/null
echo '=== SSH配置检查 ==='
grep -E '^(Port|PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config 2>/dev/null
echo '=== 可疑进程检查 ==='
ps aux | grep -E '(nc|netcat|python.*socket|bash.*dev)' | grep -v grep
"
				;;
		esac
	done
	
	# 执行远程命令
	if timeout "$REMOTE_SSH_TIMEOUT" $ssh_cmd "$ssh_user@$ssh_host" "$remote_commands" >> "$host_result_file" 2>> "$host_error_file"; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] 主机检测完成: $ssh_host" >> "$host_result_file"
		echo "SUCCESS: $ssh_host"
	else
		echo "[ERROR] 主机检测失败: $ssh_host" >> "$host_result_file"
		echo "FAILED: $ssh_host"
	fi
}

# 导出函数和变量供子进程使用
export -f remote_scan_single_host
export REMOTE_SSH_PORT REMOTE_SSH_USER REMOTE_SSH_TIMEOUT REMOTE_SSH_OPTIONS REMOTE_MODULES REMOTE_SSH_KEY

# 执行单个主机扫描
remote_scan_single_host "$1" "$2"
EOF
	
	chmod +x "$temp_script"
	
	# 读取主机列表并执行并发扫描
	local total_hosts=$(grep -v '^#' "$hosts_file" | grep -v '^[[:space:]]*$' | wc -l)
	echo -e "${BLUE}[INFO]${NC} 总共需要检测 $total_hosts 台主机"
	
	local success_count=0
	local failed_count=0
	
	# 使用xargs实现并发处理
	grep -v '^#' "$hosts_file" | grep -v '^[[:space:]]*$' | \
	xargs -I {} -P "$parallel_num" bash -c "
		result=\$($temp_script '{}' '$results_dir')
		if [[ \"\$result\" == SUCCESS:* ]]; then
			echo \"\$result\" >> '$results_dir/success.log'
		else
			echo \"\$result\" >> '$results_dir/failed.log'
		fi
		echo \"\$result\"
	"
	
	# 统计结果
	[[ -f "$results_dir/success.log" ]] && success_count=$(wc -l < "$results_dir/success.log")
	[[ -f "$results_dir/failed.log" ]] && failed_count=$(wc -l < "$results_dir/failed.log")
	
	echo -e "${GREEN}[SUCC]${NC} 批量检测完成"
	echo -e "${BLUE}[INFO]${NC} 成功: $success_count 台，失败: $failed_count 台"
	
	# 清理临时文件
	rm -f "$temp_script"
	
	log_message "INFO" "批量检测完成，成功: $success_count, 失败: $failed_count" "remoteBatchScan"
}

# 生成汇总报告
remote_generate_summary_report() {
	local results_dir="$1"
	local summary_file="$results_dir/batch_scan_summary.html"
	local current_time=$(date "+%Y-%m-%d %H:%M:%S")
	
	echo -e "${BLUE}[INFO]${NC} 正在生成汇总报告..."
	
	# 统计信息
	local total_hosts=0
	local success_count=0
	local failed_count=0
	
	[[ -f "$results_dir/success.log" ]] && success_count=$(wc -l < "$results_dir/success.log")
	[[ -f "$results_dir/failed.log" ]] && failed_count=$(wc -l < "$results_dir/failed.log")
	total_hosts=$((success_count + failed_count))
	
	# 生成HTML汇总报告
	cat > "$summary_file" << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>yinguard 远程批量检测汇总报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Microsoft YaHei', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(45deg, #2c3e50, #34495e); 
            color: white; 
            padding: 30px; 
            text-align: center;
        }
        .header h1 { 
            font-size: 2.5em; 
            margin-bottom: 10px; 
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .success { color: #27ae60; }
        .failed { color: #e74c3c; }
        .total { color: #3498db; }
        .results-section {
            padding: 30px;
        }
        .results-section h3 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.5em;
        }
        .host-list {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .host-item {
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            font-family: monospace;
        }
        .host-success { background: #d4edda; color: #155724; }
        .host-failed { background: #f8d7da; color: #721c24; }
        .footer {
            background: #34495e;
            color: white;
            padding: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
                         <h1>🛡️ 隐卫 远程批量检测汇总报告</h1>
            <p>Remote Batch Security Scan Summary Report</p>
            <p>生成时间: $current_time</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number total">$total_hosts</div>
                <div>总检测主机数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number success">$success_count</div>
                <div>检测成功</div>
            </div>
            <div class="stat-card">
                <div class="stat-number failed">$failed_count</div>
                <div>检测失败</div>
            </div>
            <div class="stat-card">
                <div class="stat-number total">$(( success_count * 100 / (total_hosts == 0 ? 1 : total_hosts) ))%</div>
                <div>成功率</div>
            </div>
        </div>
        
        <div class="results-section">
            <h3>✅ 检测成功的主机</h3>
            <div class="host-list">
EOF

	# 添加成功主机列表
	if [[ -f "$results_dir/success.log" ]]; then
		while read -r line; do
			local host=$(echo "$line" | cut -d':' -f2- | xargs)
			echo "                <div class=\"host-item host-success\">✓ $host</div>" >> "$summary_file"
		done < "$results_dir/success.log"
	else
		echo "                <div class=\"host-item\">暂无成功检测的主机</div>" >> "$summary_file"
	fi

	cat >> "$summary_file" << EOF
            </div>
            
            <h3>❌ 检测失败的主机</h3>
            <div class="host-list">
EOF

	# 添加失败主机列表
	if [[ -f "$results_dir/failed.log" ]]; then
		while read -r line; do
			local host=$(echo "$line" | cut -d':' -f2- | xargs)
			echo "                <div class=\"host-item host-failed\">✗ $host</div>" >> "$summary_file"
		done < "$results_dir/failed.log"
	else
		echo "                <div class=\"host-item\">暂无失败的主机</div>" >> "$summary_file"
	fi

	cat >> "$summary_file" << EOF
            </div>
        </div>
        
        <div class="footer">
                         <p>🛡️ 隐卫 Remote Batch Scanner | 
               📧 aiseckit@gmail.com | 
               🏢 AI安全工坊</p>
            <p style="margin-top: 10px; font-size: 0.9em; opacity: 0.8;">
                详细检测结果请查看各主机对应的日志文件
            </p>
        </div>
    </div>
</body>
</html>
EOF

	echo -e "${GREEN}[SUCC]${NC} 汇总报告生成完成: $summary_file"
	log_message "INFO" "汇总报告生成完成: $summary_file" "remoteBatchScan"
}

# 创建远程检测配置文件模板
create_remote_config_template() {
	local config_file="${1:-remote_scan.conf}"
	
	cat > "$config_file" << 'EOF'
# yinguard 远程批量检测配置文件
# =====================================

# SSH连接配置
SSH_PORT=22
SSH_USER=root
SSH_TIMEOUT=30

# SSH密钥文件路径 (如果使用密钥认证)
# SSH_KEY=/path/to/your/private/key

# SSH密码 (如果使用密码认证，不推荐在配置文件中明文保存)
# SSH_PASS=your_password

# 检测模块 (用逗号分隔)
# 可选值: system,network,psinfo,security
MODULES=system,network,psinfo,security

# SSH连接选项
SSH_OPTIONS=-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
EOF

	echo -e "${GREEN}[SUCC]${NC} 远程检测配置模板已创建: $config_file"
	echo -e "${YELLOW}[NOTE]${NC} 请根据实际环境修改配置文件"
}

# 创建主机列表文件模板
create_hosts_template() {
	local hosts_file="${1:-hosts.txt}"
	
	cat > "$hosts_file" << 'EOF'
# yinguard 远程批量检测主机列表
# ================================
# 支持以下格式:
# 1. IP地址: 192.168.1.100
# 2. IP:端口: 192.168.1.100:2222  
# 3. 用户@IP: user@192.168.1.100
# 4. 用户@IP:端口: user@192.168.1.100:2222
# 
# 以#开头的行为注释，会被忽略

# 示例主机配置
# 192.168.1.100
# 192.168.1.101:2222
# admin@192.168.1.102
# root@192.168.1.103:22
EOF

	echo -e "${GREEN}[SUCC]${NC} 主机列表模板已创建: $hosts_file"
	echo -e "${YELLOW}[NOTE]${NC} 请在文件中添加需要检测的主机信息"
}


# ========================================
# 重构说明：高级威胁检测功能已合并到增强型恶意软件检测模块中
# 原有的 advancedThreatDetection 模块功能现在通过 virusCheck 提供
# 避免重复开发，提升代码质量和维护性
# ========================================

# HTML报告生成函数

# Python包投毒检测
python_supply_chain_check() {
	echo -e "${BLUE}[INFO]${NC} 检查Python包投毒..."
	
	# Python2 pip包检测
	if command -v pip >/dev/null 2>&1; then
		local python2_malicious=$(pip freeze 2>/dev/null | grep -i -E "(istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol|beuatifulsoup|djago|fkask|httplib2|matplotlob|numppy|openssl|pilpow|psutil2|pycrypto2|pycurl2|pygments2|pyjwt2|pymongo2|pyopenssl2|python-dateutil2|python-requests|pytohn|reqeusts|requets|scapy3k|urllib3|urlib3)")
		if [[ -n "$python2_malicious" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑Python2包:"
			echo "$python2_malicious" | while read -r pkg; do
				echo -e "  ${RED}→${NC} $pkg"
				log_message "WARN" "发现可疑Python2包: $pkg" "advancedThreatDetection"
			done
		fi
	fi
	
	# Python3 pip包检测
	if command -v pip3 >/dev/null 2>&1; then
		local python3_malicious=$(pip3 freeze 2>/dev/null | grep -i -E "(istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=|aioconsol|beuatifulsoup|djago|fkask|httplib2|matplotlob|numppy|openssl|pilpow|psutil2|pycrypto2|pycurl2|pygments2|pyjwt2|pymongo2|pyopenssl2|python-dateutil2|python-requests|pytohn|reqeusts|requets|scapy3k|urllib3|urlib3)")
		if [[ -n "$python3_malicious" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑Python3包:"
			echo "$python3_malicious" | while read -r pkg; do
				echo -e "  ${RED}→${NC} $pkg"
				log_message "WARN" "发现可疑Python3包: $pkg" "advancedThreatDetection"
			done
		fi
	fi
	
	# 检查Python包安装历史
	if [[ -f "/root/.pip/pip.log" ]]; then
		local recent_installs=$(grep -i "install" /root/.pip/pip.log 2>/dev/null | tail -20)
		if [[ -n "$recent_installs" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 最近的Python包安装记录:"
			echo "$recent_installs" | while read -r install; do
				echo -e "  ${YELLOW}→${NC} $install"
			done
		fi
	fi
}

# Node.js包投毒检测
nodejs_supply_chain_check() {
	echo -e "${BLUE}[INFO]${NC} 检查Node.js包投毒..."
	
	# 检查全局npm包
	if command -v npm >/dev/null 2>&1; then
		local npm_malicious=$(npm list -g --depth=0 2>/dev/null | grep -i -E "(crossenv|babelcli|cross-env.js|d3.js|fabric-js|ffmeg|gruntcli|http-proxy-agent|mariadb|mongose|mssql.js|mssql-node|mysqljs|node-sqlite|node-tkinter|nodemailer-js|nodemailer.js|opencv4nodejs|openssl.js|proxy-agent|request-js|socket.io-js|sqlite.js|sqlserver|tkinter)")
		if [[ -n "$npm_malicious" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑Node.js全局包:"
			echo "$npm_malicious" | while read -r pkg; do
				echo -e "  ${RED}→${NC} $pkg"
				log_message "WARN" "发现可疑Node.js包: $pkg" "advancedThreatDetection"
			done
		fi
	fi
	
	# 检查package.json文件中的可疑依赖
	local package_files=$(find / -name "package.json" -type f 2>/dev/null | head -20)
	if [[ -n "$package_files" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 检查项目package.json文件:"
		echo "$package_files" | while read -r package_file; do
			local suspicious_deps=$(grep -i -E "(crossenv|babelcli|cross-env\.js|d3\.js|fabric-js|ffmeg)" "$package_file" 2>/dev/null)
			if [[ -n "$suspicious_deps" ]]; then
				echo -e "  ${RED}→${NC} 可疑依赖在 $package_file:"
				echo "    $suspicious_deps"
				log_message "WARN" "发现可疑Node.js依赖: $package_file" "advancedThreatDetection"
			fi
		done
	fi
}

# Ruby Gem包投毒检测
ruby_supply_chain_check() {
	echo -e "${BLUE}[INFO]${NC} 检查Ruby Gem包投毒..."
	
	if command -v gem >/dev/null 2>&1; then
		local gem_malicious=$(gem list 2>/dev/null | grep -i -E "(activesupport|devise|faraday|httparty|nokogiri|railties|thor)")
		if [[ -n "$gem_malicious" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 已安装的Ruby Gem包 (需人工确认版本):"
			echo "$gem_malicious" | while read -r gem; do
				echo -e "  ${YELLOW}→${NC} $gem"
			done
		fi
	fi
}

# 系统包管理器投毒检测
system_package_check() {
	echo -e "${BLUE}[INFO]${NC} 检查系统包管理器投毒..."
	
	# 检查最近安装的软件包
	if command -v dpkg >/dev/null 2>&1; then
		local recent_debs=$(grep " install " /var/log/dpkg.log 2>/dev/null | tail -20)
		if [[ -n "$recent_debs" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 最近安装的Debian包:"
			echo "$recent_debs" | while read -r pkg; do
				echo -e "  ${YELLOW}→${NC} $pkg"
			done
		fi
	fi
	
	if command -v rpm >/dev/null 2>&1; then
		local recent_rpms=$(rpm -qa --last 2>/dev/null | head -20)
		if [[ -n "$recent_rpms" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 最近安装的RPM包:"
			echo "$recent_rpms" | while read -r pkg; do
				echo -e "  ${YELLOW}→${NC} $pkg"
			done
		fi
	fi
	
	# 检查可疑的软件源
	if [[ -d "/etc/apt/sources.list.d" ]]; then
		local suspicious_sources=$(find /etc/apt/sources.list.d -name "*.list" -exec grep -l -i -E "(mining|crypto|coin|hack|exploit)" {} \; 2>/dev/null)
		if [[ -n "$suspicious_sources" ]]; then
			echo -e "${RED}[WARN]${NC} 发现可疑软件源:"
			echo "$suspicious_sources" | while read -r source; do
				echo -e "  ${RED}→${NC} $source"
				log_message "WARN" "发现可疑软件源: $source" "advancedThreatDetection"
			done
		fi
	fi
}

# 挖矿威胁检测
mining_threat_detection() {
	echo -e "${BLUE}[INFO]${NC} 正在检查挖矿威胁..."
	
	# 挖矿进程检测
	mining_process_detection
	
	# 挖矿文件检测
	mining_file_detection
	
	# 挖矿网络行为检测
	mining_network_detection
	
	# 挖矿配置文件检测
	mining_config_detection
}

# 挖矿进程检测
mining_process_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿进程..."
	
	# 常见挖矿进程特征
	local mining_processes=(
		# 知名挖矿软件
		"xmrig" "xmr-stak" "cpuminer" "minerd" "ccminer" "sgminer" "cgminer" "ethminer"
		"cryptonight" "monero" "zcash" "ethereum" "bitcoin" "nicehash" "stratum"
		# 伪装的挖矿进程
		"systemctI" "kworkerds" "watchbog" "sustse" "donate" "proxkekman" 
		"suppoie" "ririg" "ddgs" "hashvault" "kthreadd" "httpdz" "kerbero"
		"work32" "work64" "Mozz" "ntpclient" "barad_agent" "clay" "udevs"
		# 挖矿池相关
		"pool.minergate.com" "stratum+tcp" "mining.pool" "xmrpool" "moneropool"
	)
	
	for process_pattern in "${mining_processes[@]}"; do
		local mining_procs=$(ps aux | grep -v grep | grep -i "$process_pattern")
		if [[ -n "$mining_procs" ]]; then
			echo -e "${RED}[WARN]${NC} 发现挖矿进程 ($process_pattern):"
			echo "$mining_procs" | while read -r proc; do
				echo -e "  ${RED}→${NC} $proc"
				log_message "WARN" "发现挖矿进程: $proc" "advancedThreatDetection"
			done
		fi
	done
	
	# 检查高CPU占用的可疑进程
	local high_cpu_procs=$(ps aux --sort=-%cpu | head -20 | awk 'NR>1 && $3>50 {print $0}')
	if [[ -n "$high_cpu_procs" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 高CPU占用进程(>50%):"
		echo "$high_cpu_procs" | while read -r proc; do
			local cpu_usage=$(echo "$proc" | awk '{print $3}')
			local process_name=$(echo "$proc" | awk '{print $11}')
			echo -e "  ${YELLOW}→${NC} CPU:${cpu_usage}% - $process_name"
		done
	fi
}

# 挖矿文件检测
mining_file_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿文件..."
	
	# 常见挖矿文件路径和名称
	local mining_file_patterns=(
		".*xmrig.*" ".*xmr-stak.*" ".*cpuminer.*" ".*minerd.*"
		".*systemctI.*" ".*kworkerds.*" ".*watchbog.*" ".*sustse.*"
		".*cryptonight.*" ".*monero.*" ".*zcash.*" ".*ethereum.*"
		".*miner\.sh.*" ".*mining.*" ".*pool.*" ".*stratum.*"
		".*\.mine.*" ".*\.crypto.*" ".*\.coin.*"
	)
	
	for pattern in "${mining_file_patterns[@]}"; do
		local mining_files=$(find / -type f -regextype posix-extended -regex "$pattern" ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" 2>/dev/null | head -10)
		if [[ -n "$mining_files" ]]; then
			echo -e "${RED}[WARN]${NC} 发现挖矿相关文件 ($pattern):"
			echo "$mining_files" | while read -r file; do
				local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
				local file_time=$(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null)
				echo -e "  ${RED}→${NC} $file ($file_size, $file_time)"
				log_message "WARN" "发现挖矿文件: $file" "advancedThreatDetection"
			done
		fi
	done
	
	# 检查临时目录中的可疑文件
	local temp_dirs=("/tmp" "/var/tmp" "/dev/shm")
	for temp_dir in "${temp_dirs[@]}"; do
		if [[ -d "$temp_dir" ]]; then
			local suspicious_temp_files=$(find "$temp_dir" -type f -name ".*" -executable 2>/dev/null)
			if [[ -n "$suspicious_temp_files" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} $temp_dir 中的隐藏可执行文件:"
				echo "$suspicious_temp_files" | while read -r file; do
					local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
					echo -e "  ${YELLOW}→${NC} $file ($file_size)"
				done
			fi
		fi
	done
}

# 挖矿网络行为检测
mining_network_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿网络行为..."
	
	# 挖矿池端口检测
	local mining_ports=(
		"3333" "4444" "5555" "6666" "7777" "8888" "9999"
		"3367" "3377" "3636" "5730" "5740" "6688" "8008"
		"8118" "8220" "9008" "9221" "13333" "13531" "45560"
		"14444" "17777" "19999"
	)
	
	for port in "${mining_ports[@]}"; do
		local mining_connections=$(netstat -an 2>/dev/null | grep ":$port " | grep ESTABLISHED)
		if [[ -n "$mining_connections" ]]; then
			echo -e "${RED}[WARN]${NC} 发现挖矿池端口连接 ($port):"
			echo "$mining_connections" | while read -r conn; do
				echo -e "  ${RED}→${NC} $conn"
				log_message "WARN" "发现挖矿池连接: $conn" "advancedThreatDetection"
			done
		fi
	done
	
	# 检查挖矿池域名连接
	local mining_domains=(
		"pool.minergate.com" "xmrpool.eu" "moneropool.com" "nanopool.org"
		"f2pool.com" "antpool.com" "slushpool.com" "mining.pool"
		"stratum+tcp" "mining.nicehash.com" "xmr.crypto-pool.fr"
	)
	
	# 检查DNS查询记录 (如果有)
	if [[ -f "/var/log/syslog" ]]; then
		for domain in "${mining_domains[@]}"; do
			local dns_queries=$(grep -i "$domain" /var/log/syslog 2>/dev/null | tail -5)
			if [[ -n "$dns_queries" ]]; then
				echo -e "${RED}[WARN]${NC} 发现挖矿池域名查询 ($domain):"
				echo "$dns_queries" | while read -r query; do
					echo -e "  ${RED}→${NC} $query"
					log_message "WARN" "发现挖矿池域名查询: $domain" "advancedThreatDetection"
				done
			fi
		done
	fi
}

# 挖矿配置文件检测
mining_config_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查挖矿配置文件..."
	
	# 常见挖矿配置文件
	local config_files=(
		"config.json" "pools.txt" "miner.conf" "xmrig.json"
		"*.conf" "*.cfg" "start.sh" "run.sh" "mine.sh"
	)
	
	for config_pattern in "${config_files[@]}"; do
		local config_found=$(find /home /root /tmp /var/tmp -name "$config_pattern" -type f 2>/dev/null | head -10)
		if [[ -n "$config_found" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 发现配置文件 ($config_pattern):"
			echo "$config_found" | while read -r config; do
				# 检查文件内容是否包含挖矿相关关键词
				local mining_content=$(grep -i -E "(pool|stratum|mining|monero|xmr|zcash|ethereum|bitcoin|wallet|donate)" "$config" 2>/dev/null | head -3)
				if [[ -n "$mining_content" ]]; then
					echo -e "  ${RED}→${NC} $config (包含挖矿配置)"
					echo "    内容摘要: $(echo "$mining_content" | tr '\n' '; ')"
					log_message "WARN" "发现挖矿配置文件: $config" "advancedThreatDetection"
				else
					echo -e "  ${YELLOW}→${NC} $config"
				fi
			done
		fi
	done
}

# APT威胁检测
apt_threat_detection() {
	echo -e "${BLUE}[INFO]${NC} 正在检查APT威胁..."
	
	# APT后门检测
	apt_backdoor_detection
	
	# APT持久化检测
	apt_persistence_detection
	
	# APT横向移动检测
	apt_lateral_movement_detection
	
	# APT数据窃取检测
	apt_data_exfiltration_detection
}

# APT后门检测
apt_backdoor_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查APT后门..."
	
	# 检查系统关键文件的完整性
	local critical_files=(
		"/bin/bash" "/bin/sh" "/usr/bin/ssh" "/usr/sbin/sshd"
		"/bin/login" "/usr/bin/passwd" "/usr/bin/sudo"
		"/lib/systemd/systemd" "/usr/bin/systemctl"
	)
	
	for file in "${critical_files[@]}"; do
		if [[ -f "$file" ]]; then
			# 检查文件修改时间是否异常 (最近7天内修改)
			local file_age=$(find "$file" -mtime -7 2>/dev/null)
			if [[ -n "$file_age" ]]; then
				local file_time=$(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null)
				echo -e "${YELLOW}[NOTE]${NC} 系统关键文件最近被修改: $file ($file_time)"
			fi
			
			# 检查文件大小是否异常
			local file_size=$(stat -c%s "$file" 2>/dev/null)
			if [[ "$file" == "/bin/bash" && "$file_size" -gt 2000000 ]]; then
				echo -e "${RED}[WARN]${NC} /bin/bash文件大小异常: ${file_size}字节"
				log_message "WARN" "bash文件大小异常: $file_size bytes" "advancedThreatDetection"
			fi
		fi
	done
	
	# 检查异常的SUID文件
	local suspicious_suid=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E "(sudo|passwd|su|ping|mount|umount|ssh)" | head -10)
	if [[ -n "$suspicious_suid" ]]; then
		echo -e "${RED}[WARN]${NC} 发现可疑的SUID文件:"
		echo "$suspicious_suid" | while read -r suid_file; do
			local file_time=$(stat -c %y "$suid_file" 2>/dev/null || stat -f %Sm "$suid_file" 2>/dev/null)
			echo -e "  ${RED}→${NC} $suid_file ($file_time)"
			log_message "WARN" "发现可疑SUID文件: $suid_file" "advancedThreatDetection"
		done
	fi
}

# APT持久化检测
apt_persistence_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查APT持久化机制..."
	
	# 检查异常的系统服务
	if command -v systemctl >/dev/null 2>&1; then
		local suspicious_services=$(systemctl list-units --type=service --state=active | grep -v -E "(systemd|dbus|network|ssh|cron|rsyslog|udev|getty)")
		if [[ -n "$suspicious_services" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 非标准系统服务:"
			echo "$suspicious_services" | while read -r service; do
				echo -e "  ${YELLOW}→${NC} $service"
			done
		fi
	fi
	
	# 检查异常的定时任务
	local cron_files=("/etc/crontab" "/var/spool/cron/crontabs/*" "/etc/cron.d/*")
	for cron_pattern in "${cron_files[@]}"; do
		local cron_found=$(find $cron_pattern -type f 2>/dev/null)
		if [[ -n "$cron_found" ]]; then
			echo "$cron_found" | while read -r cron_file; do
				local suspicious_cron=$(grep -v "^#" "$cron_file" 2>/dev/null | grep -E "(wget|curl|python.*socket|bash.*dev|nc |netcat)")
				if [[ -n "$suspicious_cron" ]]; then
					echo -e "${RED}[WARN]${NC} 发现可疑定时任务在 $cron_file:"
					echo "$suspicious_cron" | while read -r cron; do
						echo -e "  ${RED}→${NC} $cron"
						log_message "WARN" "发现可疑定时任务: $cron" "advancedThreatDetection"
					done
				fi
			done
		fi
	done
	
	# 检查启动脚本中的异常内容
	local startup_files=("/etc/rc.local" "/etc/init.d/*" "/etc/systemd/system/*")
	for startup_pattern in "${startup_files[@]}"; do
		local startup_found=$(find $startup_pattern -type f 2>/dev/null)
		if [[ -n "$startup_found" ]]; then
			echo "$startup_found" | while read -r startup_file; do
				local suspicious_startup=$(grep -E "(wget|curl|python.*socket|bash.*dev|nc |netcat)" "$startup_file" 2>/dev/null)
				if [[ -n "$suspicious_startup" ]]; then
					echo -e "${RED}[WARN]${NC} 发现可疑启动脚本 $startup_file:"
					echo "$suspicious_startup" | while read -r startup; do
						echo -e "  ${RED}→${NC} $startup"
						log_message "WARN" "发现可疑启动脚本: $startup_file" "advancedThreatDetection"
					done
				fi
			done
		fi
	done
}

# APT横向移动检测
apt_lateral_movement_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查APT横向移动..."
	
	# 检查SSH连接记录
	if [[ -f "/var/log/auth.log" ]]; then
		local ssh_attempts=$(grep "sshd" /var/log/auth.log 2>/dev/null | grep -E "(Failed|Accepted)" | tail -20)
		if [[ -n "$ssh_attempts" ]]; then
			echo -e "${YELLOW}[NOTE]${NC} 最近的SSH连接记录:"
			echo "$ssh_attempts" | while read -r attempt; do
				echo -e "  ${YELLOW}→${NC} $attempt"
			done
		fi
	fi
	
	# 检查异常的网络连接
	local suspicious_connections=$(netstat -antp 2>/dev/null | grep ESTABLISHED | grep -E ":22|:23|:3389|:5900|:5901" | head -10)
	if [[ -n "$suspicious_connections" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 远程管理端口连接:"
		echo "$suspicious_connections" | while read -r conn; do
			echo -e "  ${YELLOW}→${NC} $conn"
		done
	fi
	
	# 检查历史命令中的横向移动迹象
	local history_files=("/root/.bash_history" "/home/*/.bash_history")
	for history_pattern in "${history_files[@]}"; do
		local history_found=$(find $history_pattern -type f 2>/dev/null)
		if [[ -n "$history_found" ]]; then
			echo "$history_found" | while read -r history_file; do
				local lateral_commands=$(grep -E "(ssh |scp |rsync |wget |curl )" "$history_file" 2>/dev/null | tail -10)
				if [[ -n "$lateral_commands" ]]; then
					echo -e "${YELLOW}[NOTE]${NC} 历史命令中的网络活动 ($history_file):"
					echo "$lateral_commands" | while read -r cmd; do
						echo -e "  ${YELLOW}→${NC} $cmd"
					done
				fi
			done
		fi
	done
}

# APT数据窃取检测
apt_data_exfiltration_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查APT数据窃取..."
	
	# 检查大文件传输
	local large_files_recently_accessed=$(find / -type f -size +100M -atime -7 2>/dev/null | head -10)
	if [[ -n "$large_files_recently_accessed" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 最近访问的大文件(>100MB):"
		echo "$large_files_recently_accessed" | while read -r file; do
			local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
			local access_time=$(stat -c %x "$file" 2>/dev/null || stat -f %Sa "$file" 2>/dev/null)
			echo -e "  ${YELLOW}→${NC} $file ($file_size, 访问时间: $access_time)"
		done
	fi
	
	# 检查压缩文件创建
	local recent_archives=$(find /tmp /var/tmp /home -name "*.tar.gz" -o -name "*.zip" -o -name "*.rar" -o -name "*.7z" -mtime -7 2>/dev/null | head -10)
	if [[ -n "$recent_archives" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 最近创建的压缩文件:"
		echo "$recent_archives" | while read -r archive; do
			local file_size=$(du -h "$archive" 2>/dev/null | cut -f1)
			local create_time=$(stat -c %y "$archive" 2>/dev/null || stat -f %Sm "$archive" 2>/dev/null)
			echo -e "  ${YELLOW}→${NC} $archive ($file_size, $create_time)"
		done
	fi
	
	# 检查敏感文件访问
	local sensitive_files=("/etc/passwd" "/etc/shadow" "/etc/hosts" "/root/.ssh/id_rsa" "/home/*/.ssh/id_rsa")
	for sensitive_pattern in "${sensitive_files[@]}"; do
		local sensitive_found=$(find $sensitive_pattern -type f -atime -1 2>/dev/null)
		if [[ -n "$sensitive_found" ]]; then
			echo -e "${RED}[WARN]${NC} 敏感文件最近被访问:"
			echo "$sensitive_found" | while read -r file; do
				local access_time=$(stat -c %x "$file" 2>/dev/null || stat -f %Sa "$file" 2>/dev/null)
				echo -e "  ${RED}→${NC} $file (访问时间: $access_time)"
				log_message "WARN" "敏感文件被访问: $file" "advancedThreatDetection"
			done
		fi
	done
}

# 高级后门检测
advanced_backdoor_detection() {
	echo -e "${BLUE}[INFO]${NC} 正在检查高级后门..."
	
	# 内核模块后门检测
	kernel_backdoor_detection
	
	# 动态库劫持检测
	library_hijacking_detection
	
	# 进程注入检测
	process_injection_detection
	
	# 隐藏文件和目录检测
	hidden_objects_detection
}

# 内核模块后门检测
kernel_backdoor_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查内核模块后门..."
	
	# 检查加载的内核模块
	local loaded_modules=$(lsmod | grep -v -E "(ext4|xfs|btrfs|overlay|bridge|iptable|netfilter|nf_|ip_|tcp_|udp_)")
	if [[ -n "$loaded_modules" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 非标准内核模块:"
		echo "$loaded_modules" | while read -r module; do
			echo -e "  ${YELLOW}→${NC} $module"
		done
	fi
	
	# 检查可疑的.ko文件
	local suspicious_ko=$(find /lib/modules -name "*.ko" -mtime -30 2>/dev/null | head -10)
	if [[ -n "$suspicious_ko" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 最近修改的内核模块:"
		echo "$suspicious_ko" | while read -r ko_file; do
			local mod_time=$(stat -c %y "$ko_file" 2>/dev/null || stat -f %Sm "$ko_file" 2>/dev/null)
			echo -e "  ${YELLOW}→${NC} $ko_file ($mod_time)"
		done
	fi
}

# 动态库劫持检测
library_hijacking_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查动态库劫持..."
	
	# 检查LD_PRELOAD环境变量
	local ld_preload_check=$(env | grep LD_PRELOAD)
	if [[ -n "$ld_preload_check" ]]; then
		echo -e "${RED}[WARN]${NC} 发现LD_PRELOAD环境变量:"
		echo -e "  ${RED}→${NC} $ld_preload_check"
		log_message "WARN" "发现LD_PRELOAD劫持: $ld_preload_check" "advancedThreatDetection"
	fi
	
	# 检查/etc/ld.so.preload文件
	if [[ -f "/etc/ld.so.preload" ]]; then
		local preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
		if [[ -n "$preload_content" ]]; then
			echo -e "${RED}[WARN]${NC} 发现ld.so.preload配置:"
			echo -e "  ${RED}→${NC} $preload_content"
			log_message "WARN" "发现ld.so.preload劫持: $preload_content" "advancedThreatDetection"
		fi
	fi
	
	# 检查系统库目录中的可疑文件
	local lib_dirs=("/lib" "/usr/lib" "/usr/local/lib")
	for lib_dir in "${lib_dirs[@]}"; do
		if [[ -d "$lib_dir" ]]; then
			local recent_libs=$(find "$lib_dir" -name "*.so*" -mtime -30 -type f 2>/dev/null | head -10)
			if [[ -n "$recent_libs" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} $lib_dir 中最近修改的库文件:"
				echo "$recent_libs" | while read -r lib; do
					local lib_time=$(stat -c %y "$lib" 2>/dev/null || stat -f %Sm "$lib" 2>/dev/null)
					echo -e "  ${YELLOW}→${NC} $lib ($lib_time)"
				done
			fi
		fi
	done
}

# 进程注入检测
process_injection_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查进程注入..."
	
	# 检查异常的进程内存映射
	local suspicious_processes=$(ps aux | awk '$3 > 1.0 {print $2}' | head -10)
	if [[ -n "$suspicious_processes" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 高CPU占用进程的内存映射检查:"
		echo "$suspicious_processes" | while read -r pid; do
			if [[ -d "/proc/$pid" ]]; then
				local maps_content=$(head -5 "/proc/$pid/maps" 2>/dev/null)
				if [[ -n "$maps_content" ]]; then
					local process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
					echo -e "  ${YELLOW}→${NC} PID:$pid ($process_name)"
				fi
			fi
		done
	fi
}

# 隐藏文件和目录检测
hidden_objects_detection() {
	echo -e "${BLUE}[INFO]${NC} 检查隐藏文件和目录..."
	
	# 检查根目录和常见目录中的隐藏文件
	local check_dirs=("/" "/tmp" "/var/tmp" "/usr" "/opt" "/home")
	for dir in "${check_dirs[@]}"; do
		if [[ -d "$dir" ]]; then
			local hidden_files=$(find "$dir" -maxdepth 2 -name ".*" -type f -size +1M 2>/dev/null | head -5)
			if [[ -n "$hidden_files" ]]; then
				echo -e "${YELLOW}[NOTE]${NC} $dir 中的大隐藏文件(>1MB):"
				echo "$hidden_files" | while read -r hidden; do
					local file_size=$(du -h "$hidden" 2>/dev/null | cut -f1)
					echo -e "  ${YELLOW}→${NC} $hidden ($file_size)"
				done
			fi
		fi
	done
	
	# 检查异常的隐藏目录
	local hidden_dirs=$(find / -maxdepth 3 -name ".*" -type d ! -path "/proc/*" ! -path "/sys/*" ! -path "/home/*/.ssh" ! -path "/root/.ssh" ! -path "/home/*/.cache" 2>/dev/null | head -10)
	if [[ -n "$hidden_dirs" ]]; then
		echo -e "${YELLOW}[NOTE]${NC} 系统中的隐藏目录:"
		echo "$hidden_dirs" | while read -r hidden_dir; do
			local dir_size=$(du -sh "$hidden_dir" 2>/dev/null | cut -f1)
			echo -e "  ${YELLOW}→${NC} $hidden_dir ($dir_size)"
		done
	fi
}

# HTML报告生成函数 - 优化版
generate_html_report() {
    local html_filename="$1"
    local html_path="${check_file}/${html_filename}"
    local current_time=$(date "+%Y-%m-%d %H:%M:%S")
    local hostname=$(hostname 2>/dev/null || echo "未知主机")
    
    echo -e "${BLUE}[INFO]${NC} 正在生成隐卫 Pro HTML报告..."
    log_message "INFO" "开始生成隐卫 Pro HTML报告: $html_path"
    
    # 收集系统信息 【增强版】
    local system_info=""
    if [[ -f "${check_file}/checkresult.txt" ]]; then
        system_info=$(head -50 "${check_file}/checkresult.txt" 2>/dev/null)
    fi
    [[ -z "$system_info" ]] && system_info="暂无检查结果数据"
    
    local ip_info=$(ip addr 2>/dev/null | grep -w inet | head -5 | sed 's/^[[:space:]]*//' || echo "IP信息获取失败")
    local os_info=$(uname -a 2>/dev/null || echo "系统信息获取失败")
    
    # 收集增强的系统信息
    local server_sn="未获取"
    if command -v dmidecode >/dev/null 2>&1; then
        server_sn=$(dmidecode -s system-serial-number 2>/dev/null | grep -v "^#" | head -1)
        [[ -z "$server_sn" || "$server_sn" == "Not Specified" ]] && server_sn="未指定"
    fi
    
    local cpu_usage="未获取"
    if command -v top >/dev/null 2>&1; then
        cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' 2>/dev/null)
        [[ -z "$cpu_usage" ]] && cpu_usage="未获取"
    fi
    
    local memory_info="未获取"
    if command -v free >/dev/null 2>&1; then
        memory_info=$(free -h | head -2 | tail -1)
    fi
    
    local disk_usage=""
    if command -v df >/dev/null 2>&1; then
        disk_usage=$(df -h | head -5)
    fi
    
    # 统计检查结果
    local total_checks=0
    local high_risk=0
    local medium_risk=0
    local low_risk=0
    
    if [[ -f "${check_file}/checkresult.txt" ]]; then
        total_checks=$(wc -l < "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
        high_risk=$(grep -c -i "高危\|critical\|high" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
        medium_risk=$(grep -c -i "中危\|medium\|warning" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
        low_risk=$(grep -c -i "低危\|low\|info" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
    fi
    
    # 统计新增功能检查结果
    local integrity_checks=$(grep -c "系统文件完整性\|文件属性安全" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
    local risk_checks=$(grep -c "风险.*检测\|漏洞检查" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
    local env_checks=$(grep -c "环境变量" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
    local network_checks=$(grep -c "网络共享\|NFS\|Samba" "${check_file}/checkresult.txt" 2>/dev/null || echo "0")
    
    # 收集详细的日志数据用于不同标签页
    local login_logs=""
    local security_logs=""
    local threat_logs=""
    local system_logs=""
    
    if [[ -f "${check_file}/checkresult.txt" ]]; then
        login_logs=$(grep -A5 -B5 "登录\|login\|ssh" "${check_file}/checkresult.txt" 2>/dev/null | head -100)
        security_logs=$(grep -A5 -B5 "安全\|security\|baseline" "${check_file}/checkresult.txt" 2>/dev/null | head -100)
        threat_logs=$(grep -A5 -B5 "威胁\|threat\|malware\|virus\|webshell" "${check_file}/checkresult.txt" 2>/dev/null | head -100)
        system_logs=$(grep -A5 -B5 "系统\|system\|process\|service" "${check_file}/checkresult.txt" 2>/dev/null | head -100)
    fi
    
    [[ -z "$login_logs" ]] && login_logs="暂无登录相关日志"
    [[ -z "$security_logs" ]] && security_logs="暂无安全检查日志"
    [[ -z "$threat_logs" ]] && threat_logs="暂无威胁检测日志"
    [[ -z "$system_logs" ]] && system_logs="暂无系统检查日志"
    
    # 创建现代化HTML报告
    cat > "$html_path" << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>隐卫 Pro 安全检测报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; 
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
            position: relative;
        }
        .header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3498db, #2ecc71, #f39c12, #e74c3c);
        }
        .header h1 { 
            font-size: 2.8em; 
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            font-weight: 700;
        }
        .header .subtitle { 
            font-size: 1.3em; 
            opacity: 0.9;
            margin-bottom: 20px;
        }
        .header .meta-info {
            display: flex;
            justify-content: space-around;
            margin-top: 25px;
            font-size: 0.95em;
            flex-wrap: wrap;
            gap: 15px;
        }
        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 8px 15px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        
        /* 标签页导航 */
        .nav-tabs {
            background: #f8f9fa;
            display: flex;
            border-bottom: 3px solid #dee2e6;
            overflow-x: auto;
        }
        .nav-tab {
            flex: 1;
            min-width: 140px;
            padding: 18px 20px;
            background: #e9ecef;
            border: none;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
            border-right: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .nav-tab:last-child { border-right: none; }
        .nav-tab:hover { 
            background: #d1ecf1; 
            transform: translateY(-2px);
        }
        .nav-tab.active { 
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
            color: white;
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(23,162,184,0.3);
        }
        
        /* 内容区域 */
        .content { 
            padding: 30px; 
        }
        .tab-content { 
            display: none; 
            animation: fadeIn 0.3s ease-in-out;
        }
        .tab-content.active { 
            display: block; 
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* 搜索功能 */
        .search-container {
            margin-bottom: 25px;
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
        }
        .search-input {
            flex: 1;
            min-width: 250px;
            padding: 12px 15px;
            border: 2px solid #dee2e6;
            border-radius: 25px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }
        .search-input:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .btn-primary { 
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white; 
        }
        .btn-primary:hover { 
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,123,255,0.3);
        }
        .btn-secondary { 
            background: linear-gradient(135deg, #6c757d 0%, #545b62 100%);
            color: white; 
        }
        .btn-secondary:hover { 
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(108,117,125,0.3);
        }
        
        /* 卡片布局 */
        .info-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); 
            gap: 25px; 
            margin-bottom: 30px;
        }
        .info-card { 
            background: #fff;
            border-radius: 12px; 
            padding: 25px; 
            border-left: 5px solid #3498db;
            transition: all 0.3s ease;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .info-card:hover { 
            transform: translateY(-5px); 
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .info-card h4 { 
            color: #2c3e50; 
            margin-bottom: 15px; 
            font-size: 1.2em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .info-card .value {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.9em;
            line-height: 1.4;
            word-break: break-all;
            border: 1px solid #e9ecef;
        }
        
        /* 状态标签 */
        .status-success { color: #28a745; font-weight: 600; }
        .status-warning { color: #ffc107; font-weight: 600; }
        .status-danger { color: #dc3545; font-weight: 600; }
        .status-info { color: #17a2b8; font-weight: 600; }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 600;
            margin: 2px 4px;
        }
        .status-badge.status-success { background: #d4edda; color: #155724; }
        .status-badge.status-warning { background: #fff3cd; color: #856404; }
        .status-badge.status-danger { background: #f8d7da; color: #721c24; }
        .status-badge.status-info { background: #d1ecf1; color: #0c5460; }
        
        /* 代码块 */
        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.6;
            overflow-x: auto;
            margin: 15px 0;
            max-height: 500px;
            overflow-y: auto;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }
        .code-block::-webkit-scrollbar { 
            width: 8px; 
            height: 8px;
        }
        .code-block::-webkit-scrollbar-track { 
            background: #4a5568; 
            border-radius: 4px;
        }
        .code-block::-webkit-scrollbar-thumb { 
            background: #718096; 
            border-radius: 4px; 
        }
        .code-block::-webkit-scrollbar-thumb:hover { 
            background: #a0aec0; 
        }
        
        /* 节展开/收起 */
        .section {
            margin-bottom: 25px;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .section-header {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 18px 25px;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }
        .section-header:hover { 
            background: linear-gradient(135deg, #218838 0%, #1e7e34 100%);
        }
        .section-header .toggle-icon {
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }
        .section-header.collapsed .toggle-icon { 
            transform: rotate(-90deg); 
        }
        .section-content {
            padding: 25px;
            background: #fff;
            border-top: 1px solid #e9ecef;
        }
        .section-content.collapsed { 
            display: none; 
        }
        
        /* 高亮搜索结果 */
        .highlight { 
            background: linear-gradient(120deg, #fff3cd 0%, #ffeaa7 100%);
            padding: 2px 4px; 
            border-radius: 3px;
            font-weight: 600;
        }
        
        /* 风险等级样式 */
        .risk-level-high { 
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            border-left-color: #dc3545; 
        }
        .risk-level-medium { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            border-left-color: #ffc107; 
        }
        .risk-level-low { 
            background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
            border-left-color: #17a2b8; 
        }
        .risk-level-safe { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border-left-color: #28a745; 
        }
        
        /* 页脚 */
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 25px;
            font-size: 0.9em;
        }
        .footer p {
            margin: 5px 0;
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .header { padding: 25px 15px; }
            .header h1 { font-size: 2.2em; }
            .header .meta-info { 
                flex-direction: column; 
                gap: 10px; 
                align-items: center;
            }
            .nav-tabs { 
                flex-direction: column; 
            }
            .nav-tab {
                min-width: auto;
                flex: none;
            }
            .info-grid { 
                grid-template-columns: 1fr; 
                gap: 15px;
            }
            .search-container { 
                flex-direction: column; 
                align-items: stretch;
            }
            .search-input {
                min-width: auto;
            }
            .content {
                padding: 20px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 隐卫 Pro 安全检测报告</h1>
            <div class="subtitle">Linux 系统全面安全评估报告</div>
            <div class="meta-info">
                <div class="meta-item">🖥️ 主机: HOSTNAME_PLACEHOLDER</div>
                <div class="meta-item">📅 生成时间: REPORT_TIME_PLACEHOLDER</div>
                <div class="meta-item">🌐 系统: SYSTEM_INFO_PLACEHOLDER</div>
                <div class="meta-item">📊 检查项: TOTAL_CHECKS_PLACEHOLDER 项</div>
            </div>
        </div>
        
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('overview')">
                📊 总览
            </button>
            <button class="nav-tab" onclick="showTab('system')">
                🖥️ 系统信息
            </button>
            <button class="nav-tab" onclick="showTab('security')">
                🔒 安全检查
            </button>
            <button class="nav-tab" onclick="showTab('threats')">
                ⚠️ 威胁检测
            </button>
            <button class="nav-tab" onclick="showTab('logs')">
                📝 日志分析
            </button>
        </div>
        
        <div class="content">
            <div class="search-container">
                <input type="text" class="search-input" id="searchInput" placeholder="🔍 搜索报告内容 (支持中英文关键词)...">
                <button class="btn btn-primary" onclick="searchContent()">
                    🔍 搜索
                </button>
                <button class="btn btn-secondary" onclick="clearSearch()">
                    🗑️ 清除
                </button>
                <button class="btn btn-secondary" onclick="toggleAllSections()">
                    📋 展开/收起
                </button>
            </div>
            
            <!-- 总览标签页 -->
            <div id="overview" class="tab-content active">
                <div class="section">
                    <div class="section-header" onclick="toggleSection(this)">
                        <span>📈 安全评估概览</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="section-content">
                        <div class="info-grid">
                            <div class="info-card risk-level-safe">
                                <h4>✅ 检查项目总数</h4>
                                <div class="value">TOTAL_CHECKS_PLACEHOLDER 项检查</div>
                                <div style="margin-top: 10px;">
                                    <span class="status-badge status-success">检查完成</span>
                                </div>
                            </div>
                            <div class="info-card risk-level-high">
                                <h4>🚨 发现高危问题</h4>
                                <div class="value">HIGH_RISK_PLACEHOLDER 个问题</div>
                                <div style="margin-top: 10px;">
                                    <span class="status-badge status-danger">需要立即处理</span>
                                </div>
                            </div>
                            <div class="info-card risk-level-medium">
                                <h4>⚠️ 发现中危问题</h4>
                                <div class="value">MEDIUM_RISK_PLACEHOLDER 个问题</div>
                                <div style="margin-top: 10px;">
                                    <span class="status-badge status-warning">建议处理</span>
                                </div>
                            </div>
                            <div class="info-card risk-level-low">
                                <h4>ℹ️ 发现低危问题</h4>
                                <div class="value">LOW_RISK_PLACEHOLDER 个问题</div>
                                <div style="margin-top: 10px;">
                                    <span class="status-badge status-info">关注即可</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="section" style="margin-top: 20px;">
                            <div class="section-header" onclick="toggleSection(this)">
                                <span>📋 新增功能统计</span>
                                <span class="toggle-icon">▼</span>
                            </div>
                            <div class="section-content">
                                <div class="info-grid">
                                    <div class="info-card">
                                        <h4>🔍 文件完整性检查</h4>
                                        <div class="value">INTEGRITY_CHECKS_PLACEHOLDER 项检查</div>
                                    </div>
                                    <div class="info-card">
                                        <h4>⚠️ 风险漏洞检查</h4>
                                        <div class="value">RISK_CHECKS_PLACEHOLDER 项检查</div>
                                    </div>
                                    <div class="info-card">
                                        <h4>🌍 环境变量检查</h4>
                                        <div class="value">ENV_CHECKS_PLACEHOLDER 项检查</div>
                                    </div>
                                    <div class="info-card">
                                        <h4>🌐 网络共享检查</h4>
                                        <div class="value">NETWORK_CHECKS_PLACEHOLDER 项检查</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 系统信息标签页 -->
            <div id="system" class="tab-content">
                <div class="section">
                    <div class="section-header" onclick="toggleSection(this)">
                        <span>🖥️ 基础系统信息</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="section-content">
                        <div class="info-grid">
                            <div class="info-card">
                                <h4>🖥️ 主机信息</h4>
                                <div class="value">HOSTNAME_PLACEHOLDER</div>
                            </div>
                            <div class="info-card">
                                <h4>💻 系统信息</h4>
                                <div class="value">SYSTEM_INFO_PLACEHOLDER</div>
                            </div>
                            <div class="info-card">
                                <h4>🌐 网络信息</h4>
                                <div class="value">NETWORK_INFO_PLACEHOLDER</div>
                            </div>
                            <div class="info-card">
                                <h4>💾 内存信息</h4>
                                <div class="value">MEMORY_INFO_PLACEHOLDER</div>
                            </div>
                        </div>
                        <div class="code-block">SYSTEM_LOGS_PLACEHOLDER</div>
                    </div>
                </div>
            </div>
            
            <!-- 安全检查标签页 -->
            <div id="security" class="tab-content">
                <div class="section">
                    <div class="section-header" onclick="toggleSection(this)">
                        <span>🔒 安全基线检查</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="section-content">
                        <div class="code-block">SECURITY_LOGS_PLACEHOLDER</div>
                    </div>
                </div>
            </div>
            
            <!-- 威胁检测标签页 -->
            <div id="threats" class="tab-content">
                <div class="section">
                    <div class="section-header" onclick="toggleSection(this)">
                        <span>⚠️ 威胁检测结果</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="section-content">
                        <div class="code-block">THREAT_LOGS_PLACEHOLDER</div>
                    </div>
                </div>
            </div>
            
            <!-- 日志分析标签页 -->
            <div id="logs" class="tab-content">
                <div class="section">
                    <div class="section-header" onclick="toggleSection(this)">
                        <span>📝 登录日志分析</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="section-content">
                        <div class="code-block">LOGIN_LOGS_PLACEHOLDER</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>🛡️ 隐卫 Pro Security Scanner v6.0.6</p>
            <p>报告生成时间: REPORT_TIME_PLACEHOLDER | 扫描完成 ✅</p>
            <p>© 2025 隐卫 Pro - 专业Linux安全检测工具</p>
        </div>
    </div>

    <script>
        // 标签页切换
        function showTab(tabName) {
            // 隐藏所有标签页内容
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            // 移除所有标签按钮的活动状态
            document.querySelectorAll('.nav-tab').forEach(btn => {
                btn.classList.remove('active');
            });
            // 显示选中的标签页
            document.getElementById(tabName).classList.add('active');
            // 激活对应的标签按钮
            event.target.classList.add('active');
        }

        // 折叠/展开节
        function toggleSection(header) {
            const content = header.nextElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.classList.contains('collapsed')) {
                content.classList.remove('collapsed');
                header.classList.remove('collapsed');
                icon.textContent = '▼';
            } else {
                content.classList.add('collapsed');
                header.classList.add('collapsed');
                icon.textContent = '▶';
            }
        }

        // 展开/收起所有节
        function toggleAllSections() {
            const headers = document.querySelectorAll('.section-header');
            const isAnyCollapsed = Array.from(headers).some(h => h.classList.contains('collapsed'));
            
            headers.forEach(header => {
                const content = header.nextElementSibling;
                const icon = header.querySelector('.toggle-icon');
                
                if (isAnyCollapsed) {
                    content.classList.remove('collapsed');
                    header.classList.remove('collapsed');
                    icon.textContent = '▼';
                } else {
                    content.classList.add('collapsed');
                    header.classList.add('collapsed');
                    icon.textContent = '▶';
                }
            });
        }

        // 搜索功能
        function searchContent() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            if (!searchTerm) return;
            
            // 清除之前的高亮
            clearSearch();
            
            // 搜索并高亮
            const textNodes = getTextNodes(document.body);
            let foundCount = 0;
            
            textNodes.forEach(node => {
                const text = node.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    const parent = node.parentNode;
                    const highlightedText = node.textContent.replace(
                        new RegExp(escapeRegExp(searchTerm), 'gi'),
                        match => `<span class="highlight">${match}</span>`
                    );
                    parent.innerHTML = parent.innerHTML.replace(node.textContent, highlightedText);
                    foundCount++;
                    
                    // 展开包含搜索结果的节
                    const section = parent.closest('.section-content');
                    if (section && section.classList.contains('collapsed')) {
                        const header = section.previousElementSibling;
                        toggleSection(header);
                    }
                    
                    // 切换到包含结果的标签页
                    const tabContent = parent.closest('.tab-content');
                    if (tabContent && !tabContent.classList.contains('active')) {
                        const tabId = tabContent.id;
                        showTab(tabId);
                    }
                }
            });
            
            if (foundCount > 0) {
                alert(`找到 ${foundCount} 个匹配结果`);
            } else {
                alert('未找到匹配的内容');
            }
        }

        // 清除搜索高亮
        function clearSearch() {
            document.querySelectorAll('.highlight').forEach(el => {
                el.outerHTML = el.innerHTML;
            });
            document.getElementById('searchInput').value = '';
        }

        // 获取所有文本节点
        function getTextNodes(node) {
            const textNodes = [];
            if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) {
                textNodes.push(node);
            } else {
                for (let i = 0; i < node.childNodes.length; i++) {
                    textNodes.push(...getTextNodes(node.childNodes[i]));
                }
            }
            return textNodes;
        }

        // 转义正则表达式特殊字符
        function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }

        // 键盘快捷键
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }
            if (e.key === 'Enter' && document.activeElement === document.getElementById('searchInput')) {
                searchContent();
            }
        });

        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', function() {
            console.log('隐卫 Pro HTML报告已加载完成');
            
            // 自动调整代码块高度
            document.querySelectorAll('.code-block').forEach(block => {
                if (block.scrollHeight > 500) {
                    block.style.maxHeight = '500px';
                    block.style.overflowY = 'auto';
                }
            });
        });
    </script>
</body>
</html>
EOF

    echo -e "${BLUE}[INFO]${NC} 正在替换HTML报告占位符..."
    
    # 安全地转义特殊字符
    hostname_escaped=$(echo "$hostname" | sed 's/[\/&]/\\&/g')
    current_time_escaped=$(echo "$current_time" | sed 's/[\/&]/\\&/g')
    os_info_escaped=$(echo "$os_info" | sed 's/[\/&]/\\&/g' | head -c 200)
    ip_info_escaped=$(echo "$ip_info" | sed 's/[\/&]/\\&/g' | head -c 200)
    memory_info_escaped=$(echo "$memory_info" | sed 's/[\/&]/\\&/g')
    
    # 替换基础占位符
    sed -i "s/HOSTNAME_PLACEHOLDER/$hostname_escaped/g" "$html_path"
    sed -i "s/REPORT_TIME_PLACEHOLDER/$current_time_escaped/g" "$html_path"
    sed -i "s/SYSTEM_INFO_PLACEHOLDER/$os_info_escaped/g" "$html_path"
    sed -i "s/NETWORK_INFO_PLACEHOLDER/$ip_info_escaped/g" "$html_path"
    sed -i "s/MEMORY_INFO_PLACEHOLDER/$memory_info_escaped/g" "$html_path"
    
    # 替换统计数据
    sed -i "s/TOTAL_CHECKS_PLACEHOLDER/$total_checks/g" "$html_path"
    sed -i "s/HIGH_RISK_PLACEHOLDER/$high_risk/g" "$html_path"
    sed -i "s/MEDIUM_RISK_PLACEHOLDER/$medium_risk/g" "$html_path"
    sed -i "s/LOW_RISK_PLACEHOLDER/$low_risk/g" "$html_path"
    
    # 替换新增功能统计
    sed -i "s/INTEGRITY_CHECKS_PLACEHOLDER/$integrity_checks/g" "$html_path"
    sed -i "s/RISK_CHECKS_PLACEHOLDER/$risk_checks/g" "$html_path"
    sed -i "s/ENV_CHECKS_PLACEHOLDER/$env_checks/g" "$html_path"
    sed -i "s/NETWORK_CHECKS_PLACEHOLDER/$network_checks/g" "$html_path"
    
    # 替换日志内容 - 使用临时文件避免特殊字符问题
    echo -e "${BLUE}[INFO]${NC} 正在处理日志内容..."
    
    # 创建临时文件
    temp_system=$(mktemp)
    temp_security=$(mktemp)
    temp_threat=$(mktemp)
    temp_login=$(mktemp)
    
    # 转义HTML特殊字符并写入临时文件
    echo "$system_logs" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' > "$temp_system"
    echo "$security_logs" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' > "$temp_security"
    echo "$threat_logs" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' > "$temp_threat"
    echo "$login_logs" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' > "$temp_login"
    
    # 使用awk安全地替换内容
    awk -v system_content="$(cat "$temp_system")" '
        /SYSTEM_LOGS_PLACEHOLDER/ { gsub(/SYSTEM_LOGS_PLACEHOLDER/, system_content); print; next }
        { print }
    ' "$html_path" > "${html_path}.tmp" && mv "${html_path}.tmp" "$html_path"
    
    awk -v security_content="$(cat "$temp_security")" '
        /SECURITY_LOGS_PLACEHOLDER/ { gsub(/SECURITY_LOGS_PLACEHOLDER/, security_content); print; next }
        { print }
    ' "$html_path" > "${html_path}.tmp" && mv "${html_path}.tmp" "$html_path"
    
    awk -v threat_content="$(cat "$temp_threat")" '
        /THREAT_LOGS_PLACEHOLDER/ { gsub(/THREAT_LOGS_PLACEHOLDER/, threat_content); print; next }
        { print }
    ' "$html_path" > "${html_path}.tmp" && mv "${html_path}.tmp" "$html_path"
    
    awk -v login_content="$(cat "$temp_login")" '
        /LOGIN_LOGS_PLACEHOLDER/ { gsub(/LOGIN_LOGS_PLACEHOLDER/, login_content); print; next }
        { print }
    ' "$html_path" > "${html_path}.tmp" && mv "${html_path}.tmp" "$html_path"
    
    # 清理临时文件
    rm -f "$temp_system" "$temp_security" "$temp_threat" "$temp_login"
    
    echo -e "${GREEN}[SUCC]${NC} 隐卫 Pro HTML报告生成成功: $html_path"
    echo -e "${BLUE}[INFO]${NC} 报告文件大小: $(du -h "$html_path" | cut -f1)"
    echo -e "${YELLOW}[INFO]${NC} 请使用浏览器打开查看: file://$html_path"
    log_message "INFO" "隐卫 Pro HTML报告生成完成: $html_path"
    
    return 0
}

# banner 函数 
echoBanner() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                      ║${NC}"
    echo -e "${BLUE}║ ██╗   ██╗██╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗      ║${NC}"
    echo -e "${BLUE}║ ╚██╗ ██╔╝██║████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗     ║${NC}"
    echo -e "${BLUE}║  ╚████╔╝ ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║     ║${NC}"
    echo -e "${BLUE}║   ╚██╔╝  ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║     ║${NC}"
    echo -e "${BLUE}║    ██║   ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝     ║${NC}"
    echo -e "${BLUE}║    ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝      ║${NC}"
    echo -e "${BLUE}║                                                                      ║${NC}"
    echo -e "${BLUE}║                  🛡️ 隐卫 Pro Security Scanner v1.0 🛡️                  ║${NC}"
    echo -e "${BLUE}║                     Linux System Security Assessment                 ║${NC}"
    echo -e "${BLUE}║                                                                      ║${NC}"
    echo -e "${BLUE}║                        Author: AI安全工坊                             ║${NC}"
    echo -e "${BLUE}║                      微信公众号: AI安全工坊                             ║${NC}"
    echo -e "${BLUE}║                                                                      ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN} USAGE:${NC}"
    echo -e "${GREEN}    1.Upload this tools to server which you want to check ${NC}"
    echo -e "${GREEN}    2.Run chmod +x YinGuard.sh ${NC}"
    echo -e "${GREEN}    3.Run ./YinGuard.sh [Options] ${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════════════════════════════${NC}"
}


# 显示使用帮助
usage() {
    echo -e "${GREEN}隐卫 安全检查工具 v1.0.0 -- 2025.08.09 ${NC}"
    echo -e "${GREEN}使用方法: bash $0 [选项]${NC}"
    echo -e "${GREEN}可用选项:${NC}"
    echo -e "${YELLOW}    -h, --help             ${GREEN}显示此帮助信息${NC}"
	echo -e "${YELLOW}    --show             	 ${GREEN}详细显示隐卫检测大纲${NC}"

	echo -e "${GREEN}  全量检查:${NC}"
    echo -e "${YELLOW}    --all                   ${GREEN}执行所有检查项并打包检查结果(推荐首次运行)${NC}"
    echo -e "${YELLOW}    --inter                 ${GREEN}启用交互模式,在执行每个模块前询问用户,该参数需要和一级模块参数联用${NC}"
	echo -e "${YELLOW}                            ${GREEN}示例: --all --inter ${NC}"

    echo -e "${GREEN}  系统相关检查:${NC}"
    echo -e "${YELLOW}    --system                ${GREEN}执行所有系统相关检查(baseinfo/user/crontab/history)${NC}"
    echo -e "${YELLOW}    --system-baseinfo       ${GREEN}检查系统基础信息(IP/版本/发行版/SN/CPU/磁盘/软件)${NC}"
    echo -e "${YELLOW}    --system-user           ${GREEN}用户信息分析(登录用户/克隆用户/非系统用户/口令检查等)${NC}"
    echo -e "${YELLOW}    --system-crontab        ${GREEN}检查计划任务(系统/用户级crontab)${NC}"
    echo -e "${YELLOW}    --system-history        ${GREEN}历史命令分析(.bash_history/.mysql_history/历史下载/敏感命令等)${NC}"

    echo -e "${GREEN}  网络相关检查:${NC}"
    echo -e "${YELLOW}    --network               ${GREEN}网络连接信息(ARP/高危端口/网络连接/DNS/路由/防火墙策略等)${NC}"

    echo -e "${GREEN}  进程相关检查:${NC}"
    echo -e "${YELLOW}    --psinfo                ${GREEN}进程信息分析(ps/top/敏感进程匹配/SSH软连接后门检测)${NC}"

    echo -e "${GREEN}  文件相关检查:${NC}"
    echo -e "${YELLOW}    --file                  ${GREEN}执行所有文件相关检查(系统服务/敏感目录/关键文件属性/各种日志文件分析)${NC}"
    echo -e "${YELLOW}    --file-systemservice    ${GREEN}系统服务检查(系统服务/用户服务/启动项等)${NC}"
    echo -e "${YELLOW}    --file-dir              ${GREEN}敏感目录检查(/tmp /root/ 隐藏文件/lsof +L1/近7天文件等)${NC}"
    echo -e "${YELLOW}    --file-keyfiles         ${GREEN}关键文件检查(SSH相关配置/环境变量检查增强/hosts/shadow/24H变动文件/特权文件等)${NC}"
    echo -e "${YELLOW}    --file-systemlog        ${GREEN}系统日志检查(message/secure/cron/yum/dmesg/btmp/lastlog/wtmp等)[/var/log]${NC}"

    echo -e "${GREEN}  后门与攻击痕迹检查:${NC}"
    echo -e "${YELLOW}    --backdoor              ${GREEN}统一后门检测(进程/文件/权限/持久化/网络/时间戳)${NC}"
	echo -e "${YELLOW}    --tunnel                ${GREEN}全面隧道检测(SSH/HTTP/DNS/ICMP/反弹shell)${NC}"
	echo -e "${YELLOW}    --tunnel-ssh 			  ${GREEN}检查SSH隧道特征${NC}"
    echo -e "${YELLOW}    --webshell              ${GREEN}WebShell 排查(关键词匹配/文件特征)${NC}"
    echo -e "${YELLOW}    --virus                 ${GREEN}增强型恶意软件检测(挖矿/后门/APT/供应链威胁全面扫描)${NC}"
    echo -e "${YELLOW}    --container-escape      ${GREEN}容器逃逸检查(权限/挂载/进程/网络安全)${NC}"
    echo -e "${YELLOW}    --memInfo               ${GREEN}内存分析(内存映射/内存马/异常使用/隐藏进程/字符串)${NC}"
    echo -e "${YELLOW}    --hackerTools           ${GREEN}黑客工具检查(自定义规则匹配)${NC}"

    echo -e "${GREEN}  其他重要检查:${NC}"
    echo -e "${YELLOW}    --kernel                ${GREEN}内核信息与安全配置检查(驱动排查)${NC}"
    echo -e "${YELLOW}    --other                 ${GREEN}其他安全项检查(可疑脚本/系统文件完整性检查/风险漏洞检查/软件排查)${NC}"
	echo -e "${YELLOW}    --performance           ${GREEN}系统性能评估(磁盘/CPU/内存/负载/流量)${NC}"

	echo -e "${GREEN}  Kubernetes 相关检查:${NC}"
    echo -e "${YELLOW}    --k8s                   ${GREEN}Kubernetes 全量安全检查${NC}"
	echo -e "${YELLOW}    --k8s-cluster           ${GREEN}Kubernetes 集群信息检查(集群信息/节点信息/服务信息等)${NC}"
	echo -e "${YELLOW}    --k8s-secret            ${GREEN}Kubernetes 集群凭据信息检查(secret/pod等)${NC}"
	echo -e "${YELLOW}    --k8s-fscan             ${GREEN}Kubernetes 集群敏感信息扫描(默认路径指定后缀文件[会备份敏感文件])${NC}"
	echo -e "${YELLOW}    --k8s-baseline          ${GREEN}Kubernetes 集群安全基线检查${NC}"
    
	echo -e "${GREEN}  系统安全基线相关:${NC}"
    echo -e "${YELLOW}    --baseline              ${GREEN}执行所有基线安全检查项${NC}"
    echo -e "${YELLOW}    --baseline-firewall     ${GREEN}防火墙策略检查(firewalld/nftables/iptables/ufw)${NC}"
    echo -e "${YELLOW}    --baseline-selinux      ${GREEN}SeLinux 策略检查${NC}"

	echo -e "${GREEN}  攻击角度信息收集[可选|默认不与--all执行]:${NC}"
    echo -e "${YELLOW}    --attack-filescan       ${GREEN}攻击角度信息收集(默认收集当前系统所有敏感文件信息)${NC}"

	echo -e "${GREEN}  远程批量检测功能:${NC}"
    echo -e "${YELLOW}    --remote-scan <hosts> <config> [parallel] ${GREEN}远程批量安全检测${NC}"
    echo -e "${YELLOW}                                  ${GREEN}hosts: 主机列表文件路径${NC}"
    echo -e "${YELLOW}                                  ${GREEN}config: 远程连接配置文件路径${NC}"
    echo -e "${YELLOW}                                  ${GREEN}parallel: 并发数量(默认5)${NC}"
    echo -e "${YELLOW}                                  ${GREEN}示例: --remote-scan hosts.txt remote_scan.conf 10${NC}"
    echo -e "${YELLOW}    --create-remote-config [file] ${GREEN}创建远程检测配置文件模板${NC}"
    echo -e "${YELLOW}    --create-hosts-template [file] ${GREEN}创建主机列表文件模板${NC}"

	echo -e "${GREEN}  报告生成功能:${NC}"
    echo -e "${YELLOW}    --html-report [filename]    ${GREEN}生成HTML格式的检查报告${NC}"
    echo -e "${YELLOW}                                  ${GREEN}如果不指定文件名,会自动生成带时间戳的文件名${NC}"
    echo -e "${YELLOW}                                  ${GREEN}示例: --html-report security_report.html${NC}"
    echo -e "${YELLOW}                                  ${GREEN}推荐用法: 先执行检查模块,再使用 --html-report 生成报告${NC}"

	echo -e "${GREEN}  文件传输功能:${NC}"
    echo -e "${YELLOW}    --send <ip> <port> <token> [file] ${GREEN}发送检查结果到远程服务器${NC}"
    echo -e "${YELLOW}                                  ${GREEN}需要提供认证token以增强安全性${NC}"
    echo -e "${YELLOW}                                  ${GREEN}如果不指定文件路径,会自动查找生成的tar.gz文件${NC}"
    echo -e "${RED}                                  ${GREEN}注意: --send必须作为唯一参数使用${NC}"
    echo -e "${RED}                                  ${GREEN}注意: --send不能与其他检查参数组合使用${NC}"
    echo -e "${YELLOW}                                  ${GREEN}示例: --send 192.168.1.100 8080 your_secret_token${NC}"
    echo -e "${YELLOW}                                  ${GREEN}示例: --send 192.168.1.100 8080 your_secret_token /path/to/file.tar.gz${NC}"
    echo -e "${YELLOW}                                  ${GREEN}推荐用法: 先执行 --all 检查,再使用 --send 发送结果${NC}"
}

# 主函数执行
main "$@"



