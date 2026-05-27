/**
 * CallManager - 通话状态管理器
 * 负责管理设备间通话状态，支持双向匹配和远程唤醒
 */
class CallManager {
    constructor(config = {}) {
        // mac => { targetMac, callerNickname, timestamp }
        this.pendingCalls = new Map();
        // mac => targetMac (双向映射)
        this.activeCalls = new Map();
        this.getConnectionByMac = null;  // (mac) => MQTTConnection
    }

    /**
     * 发起通话请求
     * @param {string} callerMac - 主叫方MAC
     * @param {string} targetMac - 被叫方MAC
     * @param {string} callerNickname - 主叫方昵称（用于远程唤醒）
     * @returns {{status: 'pending' | 'bridged', message?: string}}
     */
    requestCall(callerMac, targetMac, callerNickname) {
        // 规范化MAC地址
        callerMac = callerMac.toLowerCase();
        targetMac = targetMac.toLowerCase();

        // 检查是否已在通话中
        if (this.activeCalls.has(callerMac)) {
            return { status: 'error', message: '已在通话中' };
        }

        // 检查对方是否已请求与我通话（双向匹配）
        const pendingTarget = this.pendingCalls.get(targetMac);
        if (pendingTarget && pendingTarget.targetMac === callerMac) {
            // 双向匹配，建立桥接
            this.pendingCalls.delete(callerMac);
            this.pendingCalls.delete(targetMac);
            this.activeCalls.set(callerMac, targetMac);
            this.activeCalls.set(targetMac, callerMac);
            console.log(`通话已建立: ${callerMac} <-> ${targetMac}`);
            return { status: 'bridged' };
        }

        // 单方面请求，需要远程唤醒对方
        this.pendingCalls.set(callerMac, {
            targetMac,
            callerNickname,
            timestamp: Date.now()
        });
        console.log(`通话请求已记录: ${callerMac} -> ${targetMac}, 等待对方接听`);

        return { status: 'pending' };
    }

    /**
     * 处理被叫方加入通话
     * @param {string} calleeMac - 被叫方MAC（说"接听"的一方）
     * @returns {{status: 'bridged' | 'no_pending' | 'caller_gone' | 'error', message?: string}}
     */
    joinCall(calleeMac) {
        calleeMac = calleeMac.toLowerCase();

        // 检查是否有等待该设备加入的通话
        const pendingEntry = this.pendingCalls.get(calleeMac);
        if (!pendingEntry) {
            return { status: 'no_pending', message: '没有等待中的通话' };
        }

        const callerMac = pendingEntry.targetMac;
        // 检查主叫方是否还在pending状态
        const callerPending = this.pendingCalls.get(callerMac);
        if (!callerPending || callerPending.targetMac !== calleeMac) {
            return { status: 'caller_gone', message: '主叫方已离开或通话已超时' };
        }

        // 建立桥接
        this.pendingCalls.delete(callerMac);
        this.pendingCalls.delete(calleeMac);
        this.activeCalls.set(callerMac, calleeMac);
        this.activeCalls.set(calleeMac, callerMac);
        console.log(`通话已建立: ${callerMac} <-> ${calleeMac}`);
        return { status: 'bridged' };
    }

    /**
     * 查询设备是否在通话中或等待通话中
     */
    isInCall(mac) {
        const lowerMac = mac?.toLowerCase();
        return this.activeCalls.has(lowerMac) || this.pendingCalls.has(lowerMac);
    }

    /**
     * 获取通话对方的连接
     */
    getPeerConnection(mac) {
        const peerMac = this.activeCalls.get(mac?.toLowerCase());
        if (!peerMac || !this.getConnectionByMac) return null;
        return this.getConnectionByMac(peerMac);
    }

    /**
     * 清除设备通话状态
     * @returns {{ pendingCleared: boolean, peerMac: string|null, fromPending: boolean }}
     * 返回被清除的通话对方信息
     */
    clearDevice(mac) {
        const lowerMac = mac?.toLowerCase();

        // 检查是否在 pendingCalls 中
        const pendingEntry = this.pendingCalls.get(lowerMac);
        if (pendingEntry) {
            this.pendingCalls.delete(lowerMac);
            return { pendingCleared: true, peerMac: pendingEntry.targetMac, fromPending: true };
        }

        // 检查是否在 activeCalls 中
        const peerMac = this.activeCalls.get(lowerMac);
        if (peerMac) {
            this.activeCalls.delete(lowerMac);
            this.activeCalls.delete(peerMac);
            return { pendingCleared: false, peerMac, fromPending: false };
        }

        return { pendingCleared: false, peerMac: null, fromPending: false };
    }

    /**
     * 获取活跃通话列表
     */
    getActiveCalls() {
        const calls = [];
        for (const [mac1, mac2] of this.activeCalls) {
            if (mac1 < mac2) {
                calls.push({ device1: mac1, device2: mac2 });
            }
        }
        return calls;
    }

    /**
     * 获取等待中的通话列表
     */
    getPendingCalls() {
        return Array.from(this.pendingCalls.entries()).map(([callerMac, entry]) => ({
            callerMac,
            targetMac: entry.targetMac,
            callerNickname: entry.callerNickname,
            timestamp: entry.timestamp
        }));
    }

    /**
     * 清理超时的pending呼叫（超过timeoutMs）
     * @returns {Array} 被清理的条目数组 [{mac, entry, peerMac}]
     */
    cleanupTimeoutCalls(timeoutMs = 60000) {
        const now = Date.now();
        const cleaned = [];
        for (const [mac, entry] of this.pendingCalls) {
            if (now - entry.timestamp > timeoutMs) {
                console.log(`清理超时通话请求: ${mac} -> ${entry.targetMac}`);
                this.pendingCalls.delete(mac);
                cleaned.push({ mac, entry, peerMac: entry.targetMac });
            }
        }
        return cleaned;
    }
}

module.exports = { CallManager };